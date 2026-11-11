<?php

declare(strict_types = 1);

namespace Tests\Integration\Tenancy;

use Illuminate\Database\Eloquent\Model;
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
use SineMacula\Laravel\Iam\Authorization\AuthorizationSeams;
use SineMacula\Laravel\Iam\Contracts\TenantTree;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Tenancy\SubtreePolicyChanges;
use SineMacula\Laravel\Iam\Tenancy\TenancyContracts;
use SineMacula\Laravel\Iam\Tenancy\TreeChanges;
use SineMacula\Laravel\Iam\Testing\FakeTenantTree;
use SineMacula\Laravel\Mfa\Requirements\Requirement as MfaRequirement;
use SineMacula\Laravel\Sso\Enforcement\EnforcementService;
use Tests\Concerns\MigratesSso;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Resolvers\ClaimedTenant;
use Tests\Fixtures\Resolvers\OpenTenancy;
use Tests\Fixtures\Tenancy\ScriptedTenantRequirement;
use Tests\TestCase;

/**
 * Integration tests for a change of the application's tenant tree it reports
 * (IAM-7.5, Q7): a tenant moved under an enforcing ancestor has its sessions,
 * and those of every tenant below it, judged in the move's transaction and once
 * more once it commits, while SSO's enforcement or a tenant MFA requirement is
 * on, every other tenant's left alone; a removal, reported as the move of each
 * child moved out from under the removed tenant once written, judges those
 * children against the new structure; with neither on nothing is judged or
 * read; a tenant moved under an ancestor while the ancestor's rule is turned on
 * is judged by the change's pass after the commit, which lists the subtree
 * again; a move that rolls back revokes nothing; without a tree only the tenant
 * itself is judged; and a subtree tenant that cannot be resolved, or a tree
 * that cannot list the subtree, throws with nothing judged. The authorization
 * capability is off, its report of the move being `TenantTreeAdapterTest`'s and
 * `TreeMoveWideningTest`'s.
 *
 * Each scenario that commits runs at the connection's own level on every
 * engine, then at READ COMMITTED and REPEATABLE READ on MySQL and PostgreSQL;
 * a move that rolls back, a subtree tenant that cannot be resolved and a broken
 * subtree commit nothing, so run at the connection's own level alone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TreeChanges::class)]
#[CoversClass(SubtreePolicyChanges::class)]
#[WithConfig(TenancyContracts::TREE, FakeTenantTree::class, defer: false)]
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

    /** @var ?\SineMacula\Laravel\Iam\Testing\FakeTenantTree The application's tree. */
    private ?FakeTenantTree $tree = null;

    /**
     * Arrange SSO, the tree before the move (the enforcing root, the tenant to
     * move with its child, and a tenant that stays), and a tenancy in which
     * everyone may act in every tenant.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeSso();

        $this->tree = FakeTenantTree::fake($this->app)->place(self::ROOT)->place(self::MOVED)->place(self::CHILD, self::MOVED)->place(self::STILL);

        $this->app?->instance(TenantResolver::class, new OpenTenancy);
        $this->app?->instance(TenantAccess::class, new OpenTenancy);
    }

    /**
     * A tenant moved under an enforcing root, reported in the move's
     * transaction, has its sessions and its child's revoked there, the root's
     * compliant ones and every other tenant's left alone.
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

            $this->tree()->place(self::MOVED, self::ROOT);

            return Iam::treeChanges()->changed(self::MOVED);
        });

        self::assertSame(2, $first);

        foreach ($revoked as $session) {
            self::assertNotNull($this->stored($session)->getRevokedAt(), (string) $session->getTenantId());
        }

        self::assertNull($this->stored($kept)->getRevokedAt());
    }

    /**
     * A tenant removed, its child moved out from under it to below the
     * enforcing root and reported as moved once the restructure is written, has
     * the child's session revoked in the removal's transaction, judged against
     * the rule the new structure applies; the removed tenant's own session is
     * left to `tenantDeactivated()`, and every other tenant's alone.
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

            $children = $this->tree()->descendants(self::MOVED);

            $this->tree()->remove(self::MOVED)->place(self::CHILD, self::ROOT);

            return array_sum(array_map(static fn (string $moved): int => Iam::treeChanges()->changed($moved), $children));
        });

        self::assertSame(1, $first);
        self::assertNotNull($this->stored($child)->getRevokedAt());
        self::assertNull($this->stored($removed)->getRevokedAt());
        self::assertNull($this->stored($kept)->getRevokedAt());
    }

    /**
     * A session that enters the moved subtree after the first pass, inside the
     * move's transaction, is revoked once the move commits.
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

            $this->tree()->place(self::MOVED, self::ROOT);

            self::assertSame(0, $this->changes()->changed(self::MOVED));

            $late->newQuery()->whereKey($late->getKey())->update([$late->getTenantIdName() => self::CHILD]);
        });

        self::assertNotNull($this->stored($late)->getRevokedAt());
    }

    /**
     * A tenant moved under the root while the root's rule is being turned on,
     * after the change's first pass has listed the root's subtree and before
     * the change commits, has its sessions revoked by the change's pass after
     * the commit, which lists the subtree again.
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

            $this->tree()->place(self::MOVED, self::ROOT);
        });

        foreach ($revoked as $session) {
            self::assertNotNull($this->stored($session)->getRevokedAt(), (string) $session->getTenantId());
        }

        self::assertNull($this->stored($kept)->getRevokedAt());
    }

    /**
     * A move whose transaction rolls back revokes nothing, the second pass
     * dropped with it.
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

                $this->tree()->place(self::MOVED, self::ROOT);

                self::assertSame(1, $this->changes()->changed(self::MOVED));

                throw new \RuntimeException('The move failed.');
            });
        } catch (\RuntimeException) {
            $this->tree()->place(self::MOVED);
        }

        self::assertNull($this->stored($session)->getRevokedAt());
    }

    /**
     * With SSO's enforcement off and no tenant MFA requirement, nothing any
     * tenant requires can follow the tree: nothing is judged, and the tree is
     * not read.
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
        $before  = count($this->tree()->asked());

        $this->tree()->place(self::MOVED, self::ROOT);

        self::assertSame(0, DB::transaction(fn (): int => $this->changes()->changed(self::MOVED)));
        self::assertCount($before, $this->tree()->asked());
        self::assertNull($this->stored($session)->getRevokedAt());
    }

    /**
     * With SSO's enforcement off but a tenant MFA requirement the application
     * binds, a move judges the moved subtree against the requirement, which the
     * application may pass down its tree itself.
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

            $this->tree()->place(self::MOVED, self::ROOT);

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

        $this->app?->forgetInstance(TenantTree::class);
        $this->app?->offsetUnset(TenantTree::class);

        Config::set(TenancyContracts::TREE, null);

        $requirement->require(self::MOVED, MfaRequirement::none()->withMultifactor(300));
        $requirement->require(self::CHILD, MfaRequirement::none()->withMultifactor(300));

        DB::transaction(fn (): int => $this->changes()->changed(self::MOVED));

        self::assertNotNull($this->stored($moved)->getRevokedAt());
        self::assertNull($this->stored($child)->getRevokedAt());
    }

    /**
     * A tenant of the subtree the tenant resolver cannot resolve throws inside
     * the move's transaction, before any tenant is judged, so the move rolls
     * back with every session standing.
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

                $this->tree()->place(self::MOVED, self::ROOT);

                $this->changes()->changed(self::MOVED);
            });

            self::fail('An unresolvable tenant was judged around.');
        } catch (UnresolvedReferenceException $exception) {
            self::assertSame(ReferenceKind::TENANT, $exception->kind);
        }

        self::assertNull($this->stored($moved)->getRevokedAt());
    }

    /**
     * Rows of `[descendants]`: each answer a broken tree gives below the moved
     * tenant.
     *
     * @return iterable<string, array{0: list<string>}>
     */
    public static function provideBrokenSubtrees(): iterable
    {
        yield 'the tenant itself' => [[self::CHILD, self::MOVED]];

        yield 'an empty descendant' => [[self::CHILD, '']];

        yield 'a blank descendant' => [[self::CHILD, '  ']];

        yield 'a descendant twice' => [[self::CHILD, self::CHILD, self::STILL]];
    }

    /**
     * A tree that answers the tenant among its own descendants, a blank
     * descendant or a descendant twice is refused, with nothing judged.
     *
     * @param  list<string>  $descendants
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideBrokenSubtrees')]
    public function testABrokenSubtreeIsRefused(array $descendants): void
    {
        $this->enforceRoot();

        $tree = \Mockery::mock(TenantTree::class);

        $tree->allows('descendants')->with(self::MOVED)->andReturn($descendants);

        $this->app?->instance(TenantTree::class, $tree);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('has a cycle or is broken');

        $this->changes()->changed(self::MOVED);
    }

    /**
     * Turn SSO's enforcement on and the root's rule on, satisfied by the tests'
     * connection, which belongs to the root; answer its version.
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
     * Sign the person in with their password, acting in the tenant, and return
     * the session.
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
     * The service, as the facade reaches it.
     *
     * @return \SineMacula\Laravel\Iam\Tenancy\TreeChanges
     */
    private function changes(): TreeChanges
    {
        return Iam::treeChanges();
    }

    /**
     * The application's tree.
     *
     * @return \SineMacula\Laravel\Iam\Testing\FakeTenantTree
     */
    private function tree(): FakeTenantTree
    {
        return $this->tree ?? self::fail('The tree is not arranged.');
    }
}
