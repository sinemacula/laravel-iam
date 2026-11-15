<?php

declare(strict_types = 1);

namespace Tests\Integration\Tenancy;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Resolvers\FlatTenantTree;
use SineMacula\Laravel\Iam\Authorization\AuthorizationSeams;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Tenancy\SubtreePolicyChanges;
use SineMacula\Laravel\Iam\Tenancy\TreeChanges;
use SineMacula\Laravel\Mfa\Requirements\Requirement as MfaRequirement;
use SineMacula\Laravel\Sso\Enforcement\EnforcementService;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Models\TenantEnforcement;
use Tests\Concerns\MigratesSso;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Resolvers\ClaimedTenant;
use Tests\Fixtures\Resolvers\OpenTenancy;
use Tests\Fixtures\Tenancy\ScriptedTenantRequirement;
use Tests\Fixtures\Tenancy\StoredTenantTree;
use Tests\TestCase;

/**
 * Integration tests for application-reported tenant tree changes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TreeChanges::class)]
#[CoversClass(SubtreePolicyChanges::class)]
#[WithConfig('authorization.tenant_tree', StoredTenantTree::class, defer: false)]
#[WithConfig(AuthorizationSeams::SWITCH, false, defer: false)]
final class TreeChangesTest extends TestCase
{
    use MigratesSso, RunsAtIsolationLevels, RunsSsoFlows, SignsInPeople;

    /** @var string The enforcing root. */
    private const string ROOT = 'root';

    /** @var string The tenant that moves, from a root of its own to below the enforcing root. */
    private const string MOVED = 'moved';

    /** @var string The moved tenant's child, which moves with it. */
    private const string CHILD = 'moved-child';

    /** @var string A tenant that never moves. */
    private const string STILL = 'still';

    /**
     * Arrange SSO, the tree before the move and an open tenancy.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeSso();

        StoredTenantTree::place(self::ROOT);
        StoredTenantTree::place(self::MOVED);
        StoredTenantTree::place(self::CHILD, self::MOVED);
        StoredTenantTree::place(self::STILL);

        $this->app?->instance(TenantResolver::class, new OpenTenancy);
        $this->app?->instance(TenantAccess::class, new OpenTenancy);
    }

    /**
     * A move under an enforcing ancestor revokes the moved subtree.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAMoveUnderAnEnforcingAncestorRevokesTheMovedSubtree(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person  = $this->createPerson();
        $revoked = [$this->signInIn($person, self::MOVED), $this->signInIn($person, self::CHILD)];
        $kept    = $this->signInIn($person, self::STILL);

        $this->enforceRoot();

        $first = DB::transaction(function (): int {

            StoredTenantTree::place(self::MOVED, self::ROOT);

            return Iam::treeChanges()->changed(self::MOVED);
        });

        self::assertSame(2, $first);

        foreach ($revoked as $session) {
            self::assertNotNull($this->stored($session)->getRevokedAt(), (string) $session->getTenantId());
        }

        self::assertNull($this->stored($kept)->getRevokedAt());
    }

    /**
     * A move locks the moved tenant's SSO rule before anything else it does.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAMoveLocksTheMovedTenantsRuleFirst(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $this->enforceRoot();

        /** @var \ArrayObject<int, \Illuminate\Database\Events\QueryExecuted> $queries */
        $queries = new \ArrayObject;

        DB::transaction(function () use ($queries): void {

            StoredTenantTree::place(self::MOVED, self::ROOT);

            DB::listen(static function (QueryExecuted $query) use ($queries): void {
                $queries->append($query);
            });

            $this->changes()->changed(self::MOVED);
        });

        $first = $queries[0] ?? self::fail('The move ran no query.');

        self::assertStringContainsString('sso_enforcement', $first->sql);
        self::assertContains(self::MOVED, $first->bindings);
        self::assertTrue(TenantEnforcement::query()->where('tenant_id', self::MOVED)->exists());
        self::assertFalse(TenantEnforcement::query()->where('tenant_id', self::CHILD)->exists());
    }

    /**
     * A move committed while a sign-in locks its path judges the sign-in again
     * under the new path.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMoveCommittedWhileASignInLocksItsPathJudgesTheSignInAgain(): void
    {
        self::requireIsolationLevels();

        // The tree's plain reads are current only at READ COMMITTED
        self::useIsolationLevel('read committed');

        StoredTenantTree::place(self::TENANT, self::MOVED);

        $this->linkThroughFlow($this->createPerson());

        $tenantConnection = $this->connectionId;

        $this->enforceRoot();

        $this->connectionId = $tenantConnection;

        $handoff = $this->handoff();
        $moves   = 0;

        // The tenant's row sorts first, so the moved tenant's stays free
        DB::listen(function (QueryExecuted $query) use (&$moves): void {

            if ($moves > 0 || $query->connectionName !== self::CONNECTION || $query->connection->transactionLevel() === 0 || !self::locksARule($query)) {
                return;
            }

            $moves++;

            $this->moveUnderTheRootElsewhere();
        });

        $answer = Iam::signIns()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, new SignInContext(self::client()));

        self::assertSame(1, $moves);
        self::assertInstanceOf(RedemptionResult::class, $answer);
        self::assertSame(FailureReason::ENFORCEMENT_UNSATISFIED, $answer->reason);
    }

    /**
     * A removal is reported as the move of each child once written.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testARemovalIsReportedAsTheMoveOfEachChildOnceWritten(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person  = $this->createPerson();
        $removed = $this->signInIn($person, self::MOVED);
        $child   = $this->signInIn($person, self::CHILD);
        $kept    = $this->signInIn($person, self::STILL);

        $this->enforceRoot();

        $first = DB::transaction(function (): int {

            StoredTenantTree::remove(self::MOVED);
            StoredTenantTree::place(self::CHILD, self::ROOT);

            return Iam::treeChanges()->changed(self::CHILD);
        });

        self::assertSame(1, $first);
        self::assertNotNull($this->stored($child)->getRevokedAt());
        self::assertNull($this->stored($removed)->getRevokedAt());
        self::assertNull($this->stored($kept)->getRevokedAt());
    }

    /**
     * A session entering the subtree during the move is judged once it commits.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testASessionThatEntersTheSubtreeDuringTheMoveIsJudgedOnceItCommits(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person = $this->createPerson();
        $late   = $this->signInIn($person, self::STILL);

        $this->enforceRoot();

        DB::transaction(function () use ($late): void {

            StoredTenantTree::place(self::MOVED, self::ROOT);

            self::assertSame(0, $this->changes()->changed(self::MOVED));

            $late->newQuery()->whereKey($late->getKey())->update([$late->getTenantIdName() => self::CHILD]);
        });

        self::assertNotNull($this->stored($late)->getRevokedAt());
    }

    /**
     * A tenant moved in while the rule is turned on is judged once it commits.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testATenantMovedInWhileTheRuleIsTurnedOnIsJudgedOnceTheChangeCommits(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person  = $this->createPerson();
        $revoked = [$this->signInIn($person, self::MOVED), $this->signInIn($person, self::CHILD)];
        $kept    = $this->signInIn($person, self::STILL);

        Config::set('sso.features.enforcement', true);

        $connection = $this->makeConnection(self::ROOT);

        DB::table('sso_connections')->where('id', $connection)->update(['has_completed_sign_in' => true]);

        DB::transaction(function () use ($connection): void {

            $service = $this->app?->make(EnforcementService::class) ?? self::fail('The application has not booted.');
            $result  = $service->update(self::ROOT, true, [$connection], self::ssoClient());

            self::assertTrue($result->isChanged(), sprintf('The enforcement did not change: [%s].', $result->reason->value ?? $result->status->value));

            StoredTenantTree::place(self::MOVED, self::ROOT);
        });

        foreach ($revoked as $session) {
            self::assertNotNull($this->stored($session)->getRevokedAt(), (string) $session->getTenantId());
        }

        self::assertNull($this->stored($kept)->getRevokedAt());
    }

    /**
     * A move that rolls back revokes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMoveThatRollsBackRevokesNothing(): void
    {
        $session = $this->signInIn($this->createPerson(), self::MOVED);

        $this->enforceRoot();

        try {
            DB::transaction(function (): void {

                StoredTenantTree::place(self::MOVED, self::ROOT);

                self::assertSame(1, $this->changes()->changed(self::MOVED));

                throw new \RuntimeException('The move failed.');
            });
        } catch (\RuntimeException) {
            StoredTenantTree::place(self::MOVED);
        }

        self::assertNull($this->stored($session)->getRevokedAt());
    }

    /**
     * With neither enforcement nor a requirement nothing is judged.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testWithNeitherEnforcementNorARequirementNothingIsJudged(?string $level): void
    {
        self::runAtIsolationLevel($level);

        Config::set('sso.features.enforcement', false);

        $session = $this->signInIn($this->createPerson(), self::MOVED);

        StoredTenantTree::place(self::MOVED, self::ROOT);

        self::assertSame(0, DB::transaction(fn (): int => $this->changes()->changed(self::MOVED)));
        self::assertNull($this->stored($session)->getRevokedAt());
    }

    /**
     * A tenant requirement alone judges the moved subtree.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testATenantRequirementAloneJudgesTheMovedSubtree(?string $level): void
    {
        self::runAtIsolationLevel($level);

        Config::set('sso.features.enforcement', false);

        $person      = $this->createPerson();
        $session     = $this->signInIn($person, self::CHILD);
        $kept        = $this->signInIn($person, self::STILL);
        $requirement = ScriptedTenantRequirement::bind($this->app);

        DB::transaction(function () use ($requirement): void {

            StoredTenantTree::place(self::MOVED, self::ROOT);

            $requirement->require(self::CHILD, MfaRequirement::none()->withMultifactor(300));

            $this->changes()->changed(self::MOVED);
        });

        self::assertNotNull($this->stored($session)->getRevokedAt());
        self::assertNull($this->stored($kept)->getRevokedAt());
    }

    /**
     * Without a tree, a report judges the tenant itself alone.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testWithoutATreeOnlyTheTenantIsJudged(?string $level): void
    {
        self::runAtIsolationLevel($level);

        Config::set('sso.features.enforcement', false);

        $person      = $this->createPerson();
        $moved       = $this->signInIn($person, self::MOVED);
        $child       = $this->signInIn($person, self::CHILD);
        $requirement = ScriptedTenantRequirement::bind($this->app);

        $this->app?->instance(TenantTree::class, new FlatTenantTree);

        $requirement->require(self::MOVED, MfaRequirement::none()->withMultifactor(300));
        $requirement->require(self::CHILD, MfaRequirement::none()->withMultifactor(300));

        DB::transaction(fn (): int => $this->changes()->changed(self::MOVED));

        self::assertNotNull($this->stored($moved)->getRevokedAt());
        self::assertNull($this->stored($child)->getRevokedAt());
    }

    /**
     * An unresolvable subtree tenant throws with nothing judged.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnresolvableTenantOfTheSubtreeThrowsWithNothingJudged(): void
    {
        $person   = $this->createPerson();
        $moved    = $this->signInIn($person, self::MOVED);
        $resolver = \Mockery::mock(TenantResolver::class);

        $this->enforceRoot();

        $resolver->allows('resolve')->andReturnUsing(static fn (string $tenantId): ?Tenant => $tenantId === self::CHILD ? null : new ClaimedTenant($tenantId));

        $this->app?->instance(TenantResolver::class, $resolver);

        try {
            DB::transaction(function (): void {

                StoredTenantTree::place(self::MOVED, self::ROOT);

                $this->changes()->changed(self::MOVED);
            });

            self::fail('An unresolvable tenant was judged around.');
        } catch (UnresolvedReferenceException $exception) {
            self::assertSame(ReferenceKind::TENANT, $exception->kind);
        }

        self::assertNull($this->stored($moved)->getRevokedAt());
    }

    /**
     * Enforce the root through the tests' connection and return the version.
     *
     * @return ?string
     */
    private function enforceRoot(): ?string
    {
        Config::set('sso.features.enforcement', true);

        $connection = $this->makeConnection(self::ROOT);

        DB::table('sso_connections')->where('id', $connection)->update(['has_completed_sign_in' => true]);

        $this->connectionId = $connection;

        $service = $this->app?->make(EnforcementService::class) ?? self::fail('The application has not booted.');
        $result  = $service->update(self::ROOT, true, [$connection], self::ssoClient());

        self::assertTrue($result->isChanged(), sprintf('The enforcement did not change: [%s].', $result->reason->value ?? $result->status->value));

        return $result->enforcement?->version;
    }

    /**
     * Sign the person in, acting in the tenant, and return the session.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  string  $tenantId
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession
     *
     * @throws \Throwable
     */
    private function signInIn(Person $person, string $tenantId): EloquentSession&Model
    {
        $context = new SignInContext(self::client(), tenant: TenantSelection::of($tenantId));
        $result  = $this->sessions()->signIn('password', ['email' => $person->email, 'password' => self::PASSWORD], $context);

        self::assertTrue($result->isSignedIn(), (string) $result->reason?->value);

        return $result->session->record ?? self::fail('The sign-in established no session.');
    }

    /**
     * The session as it is stored now.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession
     */
    private function stored(EloquentSession&Model $session): EloquentSession&Model
    {
        $stored = $session->newQuery()->find($session->getKey());

        self::assertInstanceOf(EloquentSession::class, $stored);
        self::assertInstanceOf(Model::class, $stored);

        return $stored;
    }

    /**
     * Move the moved tenant under the root and report it, committed on another
     * connection.
     *
     * @return void
     *
     * @throws \Throwable
     */
    private function moveUnderTheRootElsewhere(): void
    {
        $elsewhere = 'elsewhere';
        $default   = DB::getDefaultConnection();

        Config::set('database.connections.' . $elsewhere, Config::get('database.connections.' . self::CONNECTION));
        DB::setDefaultConnection($elsewhere);

        try {
            DB::transaction(function (): void {

                StoredTenantTree::place(self::MOVED, self::ROOT);

                $this->changes()->changed(self::MOVED);
            });
        } finally {
            DB::setDefaultConnection($default);
        }
    }

    /**
     * Whether the query inserts or keeps an SSO rule's row to lock it.
     *
     * @param  \Illuminate\Database\Events\QueryExecuted  $query
     * @return bool
     */
    private static function locksARule(QueryExecuted $query): bool
    {
        return str_starts_with(strtolower($query->sql), 'insert into') && str_contains($query->sql, 'sso_enforcement');
    }

    /**
     * The service, as the facade reaches it.
     *
     * @return \SineMacula\Laravel\Iam\Tenancy\TreeChanges
     */
    private function changes(): TreeChanges
    {
        return Iam::treeChanges();
    }
}
