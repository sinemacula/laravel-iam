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
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Sso\SessionRevocationAdapter;
use SineMacula\Laravel\Iam\Tenancy\EnforcementInheritanceAdapter;
use SineMacula\Laravel\Iam\Tenancy\Membership;
use SineMacula\Laravel\Iam\Tenancy\PrincipalScopeAdapter;
use SineMacula\Laravel\Iam\Tenancy\TenancyContracts;
use SineMacula\Laravel\Iam\Tenancy\TenantMembershipAdapter;
use SineMacula\Laravel\Iam\Tenancy\TreeChanges;
use SineMacula\Laravel\Iam\Testing\FakeMemberships;
use SineMacula\Laravel\Iam\Testing\FakeTenantTree;
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
use Tests\Performance\PerformanceContractTestCase;

/**
 * The statements SSO's judgements answered from the application's memberships
 * and tenant tree make (IAM-6.8, IAM-7.4, IAM-7.5), and what an enforcement
 * change and a reported move cost across a subtree, so a read an adapter adds
 * is seen here.
 *
 * A membership judgement reads the identity once, by its key on the write
 * connection; the application's memberships cost whatever its own reads cost,
 * and the fake's none. The enforcement inheritance reads one stored rule per
 * tenant on the path, nearest first, and stops at the first that is on; the
 * application's tree costs whatever its own reads cost, and the fake's none. A
 * change across a subtree judges each tenant's sessions twice, with
 * `laravel-authentication`'s strict cut-off: its cost grows with the tenants in
 * the subtree and the sessions in them, never with any other tenant's.
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
#[WithConfig(TenancyContracts::MEMBERSHIPS, FakeMemberships::class, defer: false)]
#[WithConfig(TenancyContracts::TREE, FakeTenantTree::class, defer: false)]
final class TenancyQueryBudgetTest extends PerformanceContractTestCase
{
    use MigratesAuthorization, RunsSsoFlows, SignsInPeople;

    /** @var string The root of the tree. */
    private const string ROOT = 'root';

    /** @var string The root's region. */
    private const string REGION = 'region';

    /** @var string The region's branch, the tests' tenant's parent. */
    private const string BRANCH = 'branch';

    /** @var ?\SineMacula\Laravel\Iam\Testing\FakeTenantTree The application's tree. */
    private ?FakeTenantTree $tree = null;

    /**
     * Arrange SSO, the tree (a root, its region, the region's branch and the
     * tests' tenant below it), a tenancy in which everyone may act in every
     * tenant, and memberships holding nothing until a test grants them.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeSso();

        $this->tree = FakeTenantTree::fake($this->app)->place(self::ROOT)->place(self::REGION, self::ROOT)->place(self::BRANCH, self::REGION)->place(self::TENANT, self::BRANCH);

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

        // Reads (1): the person, by key, on the write connection; the fake
        // memberships read nothing. Writes: none.
        $standing = $this->assertQueryBudget(1, 0, static fn (): MembershipStanding => $membership->standing(self::reference($person), self::TENANT));

        self::assertNotNull($standing->acceptedAt);

        // Reads (3): the person; the grant half, `laravel-authorization`'s
        // grant scope query, reads the person again through the identity
        // directory, and every grant of the person and its principals in one
        // query, in a savepoint of its own. Writes: none.
        $judged = $this->assertQueryBudget(3, 0, static fn (): ScopeVerdict => $scope->judge(self::reference($person), self::TENANT), begins: 1, commits: 1);

        self::assertSame(ScopeVerdict::WITHIN_TENANT, $judged);
    }

    /**
     * An inheritance answer up a four-tenant path with no rule on, and with the
     * nearest ancestor's on.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnInheritanceAnswer(): void
    {
        $inheritance = $this->app?->make(EnforcementInheritance::class) ?? self::fail('The application has not booted.');

        // Reads (4): each tenant's stored rule on the path, the tenant's, its
        // branch's, region's and root's, none on; the fake tree reads nothing.
        self::assertSame(self::TENANT, $this->assertQueryBudget(4, 0, static fn (): string => $inheritance->enforcingTenant(self::TENANT, self::GUARD)));

        $this->ruleOn(self::BRANCH);

        // Reads (2): the tenant's rule, then its branch's, which is on: the
        // walk stops there.
        self::assertSame(self::BRANCH, $this->assertQueryBudget(2, 0, static fn (): string => $inheritance->enforcingTenant(self::TENANT, self::GUARD)));
    }

    /**
     * A reported move of a three-tenant subtree, with one session in each
     * tenant, to below an enforcing root.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReportedMoveOfASubtree(): void
    {
        $person  = $this->createPerson();
        $subtree = ['moved', 'moved-child', 'moved-grandchild'];

        $this->tree()->place('moved')->place('moved-child', 'moved')->place('moved-grandchild', 'moved-child');

        foreach ($subtree as $tenantId) {
            $this->signInWithPassword($person, $tenantId);
        }

        $this->ruleOn(self::ROOT);
        $this->tree()->place('moved', self::ROOT);

        $move = static fn (): int => DB::transaction(static fn (): int => Iam::treeChanges()->changed('moved'));

        // The report to laravel-authorization first. Reads (4): the moved
        // subtree, as laravel-authorization reads it, then the live grants
        // rooted in it, one read of each of its three grant tables, which hold
        // none, so nothing is reported to SSO's scope widening. First passes,
        // one savepoint per tenant, nearest the moved tenant first. Reads (9,
        // 10, 11): the tenant's live sessions' keys, locked,
        // and the sessions; the person, twice; the policy's reads of the rule
        // up the path (the tenant's own, each ancestor's up to the enforcing
        // root's, then the root's rule again with its connections, so one more
        // for each level down); and the session's provenance connection, once,
        // shared by the policy and laravel-authentication's judgement.
        // Writes (1 each): the session revoked. Second passes, once the move
        // commits, one transaction per tenant: each reads the tenant's live
        // sessions' keys and finds none left (3). Transactions: the move's, and
        // six of laravel-authentication's.
        $revoked = $this->assertQueryBudget(37, 3, $move, begins: 7, commits: 7);

        self::assertSame(3, $revoked);
    }

    /**
     * Turn the tenant's rule on, satisfied by a connection of its own marked as
     * having completed a sign-in.
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
     * The application's tree.
     *
     * @return \SineMacula\Laravel\Iam\Testing\FakeTenantTree
     */
    private function tree(): FakeTenantTree
    {
        return $this->tree ?? self::fail('The tree is not arranged.');
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
