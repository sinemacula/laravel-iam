<?php

declare(strict_types = 1);

namespace Tests\Performance\Tenancy;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;
use SineMacula\Laravel\Iam\Contracts\Memberships;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Sso\SessionRevocationAdapter;
use SineMacula\Laravel\Iam\Tenancy\EnforcementInheritanceAdapter;
use SineMacula\Laravel\Iam\Tenancy\Membership;
use SineMacula\Laravel\Iam\Tenancy\PrincipalScopeAdapter;
use SineMacula\Laravel\Iam\Tenancy\TenantMembershipAdapter;
use SineMacula\Laravel\Iam\Tenancy\TreeChanges;
use SineMacula\Laravel\Iam\Testing\FakeMemberships;
use SineMacula\Laravel\Sso\Contracts\EnforcementInheritance;
use SineMacula\Laravel\Sso\Contracts\PrincipalScope;
use SineMacula\Laravel\Sso\Contracts\TenantMembership;
use SineMacula\Laravel\Sso\Enforcement\EnforcementService;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict;
use SineMacula\Laravel\Sso\Linking\MembershipStanding;
use Tests\Concerns\MigratesAuthorization;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Resolvers\OpenTenancy;
use Tests\Fixtures\Tenancy\StoredTenantTree;
use Tests\Performance\PerformanceContractTestCase;

/**
 * Query budgets for SSO's judgements from memberships and the tenant tree.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TenantMembershipAdapter::class)]
#[CoversClass(PrincipalScopeAdapter::class)]
#[CoversClass(EnforcementInheritanceAdapter::class)]
#[CoversClass(SessionRevocationAdapter::class)]
#[CoversClass(TreeChanges::class)]
#[WithConfig('authorization.tenant_tree', StoredTenantTree::class, defer: false)]
final class TenancyQueryBudgetTest extends PerformanceContractTestCase
{
    use MigratesAuthorization, RunsSsoFlows, SignsInPeople;

    /** @var string The root of the tree. */
    private const string ROOT = 'root';

    /** @var string The root's region. */
    private const string REGION = 'region';

    /** @var string The region's branch, the tests' tenant's parent. */
    private const string BRANCH = 'branch';

    /**
     * Arrange SSO, the tree, an open tenancy and empty memberships.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeSso();

        StoredTenantTree::place(self::ROOT);
        StoredTenantTree::place(self::REGION, self::ROOT);
        StoredTenantTree::place(self::BRANCH, self::REGION);
        StoredTenantTree::place(self::TENANT, self::BRANCH);

        $this->app?->instance(TenantResolver::class, new OpenTenancy);
        $this->app?->instance(TenantAccess::class, new OpenTenancy);
    }

    /**
     * A tenant membership standing, and a principal scope judgement.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMembershipJudgement(): void
    {
        $person = $this->createPerson();

        FakeMemberships::fake($this->app)->grant($person, Membership::of(self::TENANT, CarbonImmutable::now()));

        $app        = $this->app ?? self::fail('The application has not booted.');
        $membership = $app->make(TenantMembership::class);
        $scope      = $app->make(PrincipalScope::class);

        // One read: the person by key; the fake memberships read nothing.
        $standing = $this->assertQueryBudget(1, 0, static fn (): MembershipStanding => $membership->standing(self::reference($person), self::TENANT));

        self::assertNotNull($standing->acceptedAt);

        // Reads: the person, then the grant scope query's person, the tenant's
        // children and the grants, in a savepoint.
        $judged = $this->assertQueryBudget(4, 0, static fn (): ScopeVerdict => $scope->judge(self::reference($person), self::TENANT), begins: 1, commits: 1);

        self::assertSame(ScopeVerdict::WITHIN_TENANT, $judged);
    }

    /**
     * An inheritance answer up a four-tenant path.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnInheritanceAnswer(): void
    {
        $inheritance = $this->app?->make(EnforcementInheritance::class) ?? self::fail('The application has not booted.');

        // The tenant's rule, four tree reads, then three ancestors' rules.
        self::assertSame(self::TENANT, $this->assertQueryBudget(8, 0, static fn (): string => $inheritance->enforcingTenant(self::TENANT, self::GUARD)));

        $this->ruleOn(self::BRANCH);

        // The tenant's rule, four tree reads, then the branch's, which is on.
        self::assertSame(self::BRANCH, $this->assertQueryBudget(6, 0, static fn (): string => $inheritance->enforcingTenant(self::TENANT, self::GUARD)));
    }

    /**
     * A reported move of a three-tenant subtree under an enforcing root.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReportedMoveOfASubtree(): void
    {
        $person  = $this->createPerson();
        $subtree = ['moved', 'moved-child', 'moved-grandchild'];

        StoredTenantTree::place('moved');
        StoredTenantTree::place('moved-child', 'moved');
        StoredTenantTree::place('moved-grandchild', 'moved-child');

        foreach ($subtree as $tenantId) {
            $this->signInWithPassword($person, $tenantId);
        }

        $this->ruleOn(self::ROOT);
        StoredTenantTree::place('moved', self::ROOT);

        $move = static fn (): int => DB::transaction(static fn (): int => Iam::treeChanges()->changed('moved'));

        // Reads: the grant report (4), the subtree (4), first passes of 11, 13
        // and 15 (sessions, person, rule up the path, provenance), second
        // passes (3) and the subtree again (4). Writes: one revocation per
        // tenant.
        // Transactions: three savepoints and six of laravel-authentication's.
        $revoked = $this->assertQueryBudget(54, 3, $move, begins: 9, commits: 9);

        self::assertSame(3, $revoked);
    }

    /**
     * Bind the application's memberships before the seams are bound.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $app->bind(Memberships::class, FakeMemberships::class);
    }

    /**
     * Turn the tenant's rule on through a connection of its own.
     *
     * @param  string  $tenantId
     * @return void
     */
    private function ruleOn(string $tenantId): void
    {
        Config::set('sso.features.enforcement', true);

        $connection = $this->makeConnection($tenantId);

        DB::table('sso_connections')->where('id', $connection)->update(['has_completed_sign_in' => true]);

        $service = $this->app?->make(EnforcementService::class) ?? self::fail('The application has not booted.');

        self::assertTrue($service->update($tenantId, true, [$connection], self::ssoClient())->isChanged());
    }

    /**
     * Sign the person in with their password, acting in the tenant.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  string  $tenantId
     * @return void
     *
     * @throws \Throwable
     */
    private function signInWithPassword(Person $person, string $tenantId): void
    {
        $context = new SignInContext(self::client(), tenant: TenantSelection::of($tenantId));

        self::assertTrue($this->sessions()->signIn('password', ['email' => $person->email, 'password' => self::PASSWORD], $context)->isSignedIn());
    }

    /**
     * The reference SSO names the person by.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return \SineMacula\Laravel\Sso\Identities\IdentityReference
     */
    private static function reference(Person $person): IdentityReference
    {
        return new IdentityReference($person->getMorphClass(), (string) $person->id);
    }
}
