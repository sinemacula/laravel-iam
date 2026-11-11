<?php

declare(strict_types = 1);

namespace Tests\Integration\Tenancy;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;
use SineMacula\Laravel\Iam\Authorization\AuthorizationSeams;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Sso\SessionRevocationAdapter;
use SineMacula\Laravel\Iam\Tenancy\SubtreePolicyChanges;
use SineMacula\Laravel\Iam\Tenancy\TreeChanges;
use SineMacula\Laravel\Sso\Enforcement\EnforcementService;
use Tests\Concerns\MigratesSso;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Resolvers\OpenTenancy;
use Tests\Fixtures\Tenancy\StoredTenantTree;
use Tests\TestCase;

/**
 * Integration tests for a move of a tenant racing a change of an ancestor's
 * rule (IAM-7.5, Q7), with the application's tenant tree held in the database:
 * the root's rule is turned on, and once the change's first pass has listed the
 * root's subtree, which the moved tenant is not yet in, and read the root's
 * sessions, the tenant is moved under the root on another connection to the
 * same database and the move reported and committed there. The move's passes
 * read the root's rule as it was, the change not yet committed, and revoke
 * nothing; the change's pass after its commit lists the subtree again, finds
 * the moved tenant, and revokes its password session, which the rule now
 * refuses, by the time the change has committed.
 *
 * Run at READ COMMITTED and REPEATABLE READ on MySQL and PostgreSQL, the move
 * committing inside the change on each, since the move's reads take no lock the
 * change holds. The authorization capability is off, its report of a move being
 * `TreeMoveWideningTest`'s.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SubtreePolicyChanges::class)]
#[CoversClass(SessionRevocationAdapter::class)]
#[CoversClass(TreeChanges::class)]
#[WithConfig('authorization.tenant_tree', StoredTenantTree::class, defer: false)]
#[WithConfig(AuthorizationSeams::SWITCH, false, defer: false)]
final class TreeMoveRaceTest extends TestCase
{
    use MigratesSso, RunsAtIsolationLevels, RunsSsoFlows, SignsInPeople;

    /** @var string The root, whose rule is turned on. */
    private const string ROOT = 'root';

    /** @var string The tenant moved under the root while its rule is turned on. */
    private const string MOVED = 'moved';

    /** @var string The second connection the move is made on. */
    private const string ELSEWHERE = 'elsewhere';

    /** @var ?string The root's connection, which its rule names. */
    private ?string $rootConnection = null;

    /**
     * Arrange SSO with its enforcement on and no rule yet, the root and the
     * tenant to move each a root of the stored tree, a tenancy in which
     * everyone may act in every tenant, and the root's connection marked as
     * having completed a sign-in, so SSO may enforce it.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        self::requireIsolationLevels();

        $this->arrangeSso();

        Config::set('sso.features.enforcement', true);

        StoredTenantTree::place(self::ROOT);
        StoredTenantTree::place(self::MOVED);

        $this->app?->instance(TenantResolver::class, new OpenTenancy);
        $this->app?->instance(TenantAccess::class, new OpenTenancy);

        $this->rootConnection = $this->makeConnection(self::ROOT);

        DB::table('sso_connections')->where('id', $this->rootConnection)->update(['has_completed_sign_in' => true]);
    }

    /**
     * Roll back what is left open on the other connection, so the migrations'
     * rollback never waits on it.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $elsewhere = $this->app?->make('db')->getConnections()[self::ELSEWHERE] ?? null;

        while ($elsewhere !== null && $elsewhere->transactionLevel() > 0) {
            $elsewhere->rollBack();
        }

        parent::tearDown();
    }

    /**
     * A tenant moved under the root, and its move committed, while the root's
     * rule is being turned on has its password session revoked by the time the
     * change has committed, though neither the move's passes nor the change's
     * first pass judged it under the rule.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testATenantMovedUnderTheRootWhileItsRuleIsTurnedOnIsRevoked(string $level): void
    {
        self::useIsolationLevel($level);

        $session = $this->signInIn(self::MOVED);
        /** @var \ArrayObject<int, int> $moves */
        $moves = new \ArrayObject;

        $this->onceTheChangeHasReadTheRoot($level, function () use ($moves): void {

            $moves->append($this->moveElsewhere());
        });

        $service = $this->app?->make(EnforcementService::class) ?? self::fail('The application has not booted.');
        $result  = $service->update(self::ROOT, true, [(string) $this->rootConnection], self::ssoClient());

        self::assertTrue($result->isChanged(), sprintf('The enforcement did not change: [%s].', $result->reason->value ?? $result->status->value));
        self::assertSame([0], $moves->getArrayCopy(), 'The move did not run while the change did, or judged the rule the change had not committed.');

        $stored = DB::table('authentication_sessions')->where('id', $session)->first() ?? self::fail('The session was not committed.');

        self::assertNotNull($stored->revoked_at, 'The session of the tenant moved under the root during the change still stands.');
        self::assertSame(RevocationReason::TENANT_POLICY_CHANGED->value, $stored->revoked_reason);
    }

    /**
     * Sign a person in with their password, acting in the tenant, and answer
     * the session's key.
     *
     * @param  string  $tenantId
     * @return string
     *
     * @throws \Throwable
     */
    private function signInIn(string $tenantId): string
    {
        $person  = $this->createPerson();
        $context = new SignInContext(self::client(), tenant: TenantSelection::of($tenantId));
        $result  = $this->sessions()->signIn('password', ['email' => $person->email, 'password' => self::PASSWORD], $context);

        self::assertTrue($result->isSignedIn(), (string) $result->reason?->value);

        return self::keyOf($result->session->record ?? self::fail('The sign-in established no session.'));
    }

    /**
     * Move the tenant under the root inside a transaction on the other
     * connection, made the default (and so every member's storage connection)
     * while it runs, report the move there, and commit it; answer how many
     * sessions the move's first pass revoked.
     *
     * @return int
     *
     * @throws \Throwable
     */
    private function moveElsewhere(): int
    {
        $default   = DB::getDefaultConnection();
        $elsewhere = DB::connection(self::ELSEWHERE);

        DB::setDefaultConnection(self::ELSEWHERE);

        try {
            $elsewhere->beginTransaction();

            StoredTenantTree::place(self::MOVED, self::ROOT);

            $revoked = Iam::treeChanges()->changed(self::MOVED);

            $elsewhere->commit();

            return $revoked;
        } finally {
            while ($elsewhere->transactionLevel() > 0) {
                $elsewhere->rollBack();
            }

            DB::setDefaultConnection($default);
        }
    }

    /**
     * Once the change's first pass has listed the root's subtree and read the
     * keys of the root's live sessions with its locking read, inside the
     * change's transaction, run the move on the other connection, at the level
     * given.
     *
     * @param  string  $level
     * @param  \Closure(): void  $move
     * @return void
     */
    private function onceTheChangeHasReadTheRoot(string $level, \Closure $move): void
    {
        Config::set('database.connections.' . self::ELSEWHERE, Config::get('database.connections.' . self::CONNECTION));

        $elsewhere = DB::connection(self::ELSEWHERE);

        // Never wait long on a lock the change holds.
        $elsewhere->statement($elsewhere->getDriverName() === 'pgsql' ? 'set lock_timeout = \'5s\'' : 'set session innodb_lock_wait_timeout = 5');

        self::useIsolationLevel($level, self::ELSEWHERE);

        $ran = false;

        DB::connection(self::CONNECTION)->listen(static function (QueryExecuted $query) use (&$ran, $move): void {

            if ($ran || !self::readsTheRootsSessions($query)) {
                return;
            }

            $ran = true;

            $move();
        });
    }

    /**
     * Whether the query is the change's first pass's locking read of the keys
     * of the root's live sessions, made on the test's connection inside the
     * change's transaction.
     *
     * @param  \Illuminate\Database\Events\QueryExecuted  $query
     * @return bool
     */
    private static function readsTheRootsSessions(QueryExecuted $query): bool
    {
        $sql = strtolower($query->sql);

        return $query->connectionName === self::CONNECTION
            && $query->connection->transactionLevel() > 0
            && str_contains($sql, 'authentication_sessions')
            && str_contains($sql, 'tenant_id')
            && str_contains($sql, 'for update')
            && in_array(self::ROOT, $query->bindings, true);
    }
}
