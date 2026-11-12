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
 * Integration tests for a tenant move racing an ancestor's rule change.
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
     * Arrange SSO enforcement, two stored roots and an open tenancy.
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
     * Roll back what is left open, so the migrations' rollback never waits.
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
     * A tenant moved under the root while its rule is turned on is revoked.
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
     * Sign a person in, acting in the tenant, and return the session key.
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
     * Move and report the tenant elsewhere; return the revocations.
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
     * Run the move once the change's first pass has read the root's sessions.
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
     * Whether the query is the first pass's locking read of the root.
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
