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
 * The statements SSO's judgements answered from the application's memberships
 * and tenant tree make (IAM-6.8, IAM-7.4, IAM-7.5), and what an enforcement
 * change and a reported move cost across a subtree, so a read an adapter adds
 * is seen here. The tests' tree is stored, so its own reads are counted too:
 * one per ancestor walked, and one per tenant whose children a subtree lists.
 *
 * A membership judgement reads the identity once, by its key on the write
 * connection; the application's memberships cost whatever its own reads cost,
 * and the fake's none. The enforcement inheritance reads one stored rule per
 * tenant on the path, nearest first, and stops at the first that is on. A
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

        // Reads (1): the person, by key, on the write connection; the fake
        // memberships read nothing. Writes: none.
        $standing = $this->assertQueryBudget(1, 0, static fn (): MembershipStanding => $membership->standing(self::reference($person), self::TENANT));

        self::assertNotNull($standing->acceptedAt);

        // Reads (4): the person; the grant half, `laravel-authorization`'s
        // grant scope query, reads the person again through the identity
        // directory, the stored tree's children of the tenant, and every grant
        // of the person and its principals in one query, in a savepoint of its
        // own. Writes: none.
        $judged = $this->assertQueryBudget(4, 0, static fn (): ScopeVerdict => $scope->judge(self::reference($person), self::TENANT), begins: 1, commits: 1);

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

        // Reads (8): the tenant's stored rule; the stored tree's four reads up
        // to the root; then the branch's, region's and root's rules, none on.
        self::assertSame(self::TENANT, $this->assertQueryBudget(8, 0, static fn (): string => $inheritance->enforcingTenant(self::TENANT, self::GUARD)));

        $this->ruleOn(self::BRANCH);

        // Reads (6): the tenant's rule, the stored tree's four reads, then its
        // branch's rule, which is on: the walk stops there.
        self::assertSame(self::BRANCH, $this->assertQueryBudget(6, 0, static fn (): string => $inheritance->enforcingTenant(self::TENANT, self::GUARD)));
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

        StoredTenantTree::place('moved');
        StoredTenantTree::place('moved-child', 'moved');
        StoredTenantTree::place('moved-grandchild', 'moved-child');

        foreach ($subtree as $tenantId) {
            $this->signInWithPassword($person, $tenantId);
        }

        $this->ruleOn(self::ROOT);
        StoredTenantTree::place('moved', self::ROOT);

        $move = static fn (): int => DB::transaction(static fn (): int => Iam::treeChanges()->changed('moved'));

        // The stored tree lists a subtree in four reads: each tenant's
        // children, then the typed rows. The report to laravel-authorization
        // first. Reads (7): the moved subtree, then the live grants rooted in
        // it, one read of each of its three grant tables, which hold none, so
        // nothing is reported to SSO's scope widening. The subtree again (4).
        // First passes, one savepoint per tenant, nearest the moved tenant
        // first. Reads (11, 13, 15): the tenant's live sessions' keys, locked,
        // and the sessions; the person, twice; the policy's reads of the rule
        // up the path (the tenant's own, the stored tree's walk to the root,
        // each ancestor's up to the enforcing root's, then the root's rule
        // again with its connections); and the session's provenance connection,
        // once, shared by the policy and laravel-authentication's judgement.
        // Writes (1 each): the session revoked. Second passes, once the move
        // commits: the subtree again (4), then one transaction per tenant, each
        // reading the tenant's live sessions' keys and finding none left (3).
        // Transactions: the move's, and six of laravel-authentication's.
        $revoked = $this->assertQueryBudget(57, 3, $move, begins: 7, commits: 7);

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
