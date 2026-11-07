<?php

declare(strict_types = 1);

namespace Tests\Integration\Tenancy;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;
use SineMacula\Laravel\Iam\Contracts\TenantTree;
use SineMacula\Laravel\Iam\Exceptions\TenancyMisconfiguredException;
use SineMacula\Laravel\Iam\Sso\SessionRevocationAdapter;
use SineMacula\Laravel\Iam\Tenancy\EnforcementInheritanceAdapter;
use SineMacula\Laravel\Iam\Tenancy\SubtreePolicyChanges;
use SineMacula\Laravel\Iam\Tenancy\TenancyContracts;
use SineMacula\Laravel\Iam\Testing\FakeTenantTree;
use SineMacula\Laravel\Sso\Contracts\Enforcement;
use SineMacula\Laravel\Sso\Contracts\EnforcementExemption;
use SineMacula\Laravel\Sso\Contracts\EnforcementInheritance;
use SineMacula\Laravel\Sso\Enforcement\EnforcementLock;
use SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy;
use SineMacula\Laravel\Sso\Enforcement\EnforcementService;
use SineMacula\Laravel\Sso\Events\EnforcementChanged;
use SineMacula\Laravel\Sso\Events\ExemptionUsed;
use SineMacula\Laravel\Sso\Models\TenantEnforcement;
use Tests\Concerns\MigratesSso;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Resolvers\OpenTenancy;
use Tests\Fixtures\Tenancy\ExemptsIdentities;
use Tests\TestCase;

/**
 * Integration tests for SSO's enforcement inheritance, answered from the
 * application's tenant tree (IAM-7.5), and for the enforcement change that
 * judges every tenant below the enforcing one: the nearest tenant, from the one
 * asked up through its ancestors, that has a rule enforces, and the tenant
 * itself when none has; a rule turned off keeps the question at its tenant, so
 * turning an inner rule off under an enforcing ancestor only loosens what
 * applies below it, while a tenant never configured, or holding only the row
 * SSO's lock inserts, passes it up; a tree with a cycle is refused and none
 * configured throws; a password sign-in in a tenant whose ancestor enforces is
 * `sso_required`; and turning an ancestor's rule on revokes, in its own
 * transaction, the sessions it no longer allows in that tenant and every tenant
 * below it, whatever any setting says, keeping an exempt person's and every
 * session elsewhere, while turning it off revokes nothing.
 *
 * The tree is a root with a region, the region with a branch, the branch with
 * the tests' tenant, and a second root apart. Each scenario that changes rules
 * and then reads the inheritance or judges sign-ins and sessions runs at the
 * connection's own level on every engine, then at READ COMMITTED and REPEATABLE
 * READ on MySQL and PostgreSQL; SSO's policy naming the enforcing ancestor, the
 * row SSO's lock inserts and a broken tree run at the connection's own level
 * alone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EnforcementInheritanceAdapter::class)]
#[CoversClass(SessionRevocationAdapter::class)]
#[CoversClass(SubtreePolicyChanges::class)]
#[WithConfig(TenancyContracts::TREE, FakeTenantTree::class, defer: false)]
final class EnforcementInheritanceAdapterTest extends TestCase
{
    use MigratesSso, RunsAtIsolationLevels, RunsSsoFlows, SignsInPeople;

    /** @var string The root of the tree. */
    private const string ROOT = 'root';

    /** @var string The root's region. */
    private const string REGION = 'region';

    /** @var string The region's branch, the tests' tenant's parent. */
    private const string BRANCH = 'branch';

    /** @var string A root apart from the tree. */
    private const string APART = 'apart';

    /** @var ?\SineMacula\Laravel\Iam\Testing\FakeTenantTree The application's tree. */
    private ?FakeTenantTree $tree = null;

    /** @var array<string, string> The connection made for each tenant whose rule a test stores. */
    private array $connections = [];

    /** @var ?\Tests\Fixtures\Tenancy\ExemptsIdentities The application's break-glass rule. */
    private ?ExemptsIdentities $exemptions = null;

    /**
     * Arrange SSO with its enforcement on and no rule yet, the tree, a tenancy
     * in which everyone may act in every tenant, and an exemption rule
     * exempting nobody until a test says so.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeSso();

        Config::set('sso.features.enforcement', true);

        $this->tree = FakeTenantTree::fake($this->app)
            ->place(self::ROOT)
            ->place(self::REGION, self::ROOT)
            ->place(self::BRANCH, self::REGION)
            ->place(self::TENANT, self::BRANCH)
            ->place(self::APART);

        $this->exemptions = new ExemptsIdentities;

        $this->app?->instance(TenantResolver::class, new OpenTenancy);
        $this->app?->instance(TenantAccess::class, new OpenTenancy);
        $this->app?->instance(EnforcementExemption::class, $this->exemptions);

        Event::fake([ExemptionUsed::class, EnforcementChanged::class]);
    }

    /**
     * The adapter is SSO's enforcement inheritance while a tree is named.
     *
     * @return void
     */
    public function testTheAdapterIsSsosEnforcementInheritance(): void
    {
        self::assertInstanceOf(EnforcementInheritanceAdapter::class, $this->resolved(EnforcementInheritance::class));
    }

    /**
     * The nearest tenant, from the one asked up, that has a rule enforces; a
     * tenant's own rule is the nearest; with none stored up the path, the
     * tenant enforces itself; a rule turned off still keeps the question at its
     * tenant.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testTheNearestTenantWithARuleEnforces(?string $level): void
    {
        self::runAtIsolationLevel($level);

        self::assertSame(self::TENANT, $this->enforcing(self::TENANT));

        $this->rule(self::ROOT, true);

        self::assertSame(self::ROOT, $this->enforcing(self::TENANT));
        self::assertSame(self::ROOT, $this->enforcing(self::REGION));
        self::assertSame(self::ROOT, $this->enforcing(self::ROOT));
        self::assertSame(self::APART, $this->enforcing(self::APART));

        $this->rule(self::REGION, true);

        self::assertSame(self::REGION, $this->enforcing(self::TENANT));
        self::assertSame(self::REGION, $this->enforcing(self::BRANCH));
        self::assertSame(self::ROOT, $this->enforcing(self::ROOT));

        $this->rule(self::TENANT, true);

        self::assertSame(self::TENANT, $this->enforcing(self::TENANT));
        self::assertSame(self::REGION, $this->enforcing(self::BRANCH));

        $this->rule(self::TENANT, false);
        $this->rule(self::REGION, false);

        self::assertSame(self::TENANT, $this->enforcing(self::TENANT));
        self::assertSame(self::REGION, $this->enforcing(self::BRANCH));
        self::assertSame(self::ROOT, $this->enforcing(self::ROOT));

        $this->rule(self::ROOT, false);

        self::assertSame(self::REGION, DB::transaction(fn (): string => $this->enforcing(self::BRANCH)));
    }

    /**
     * A tenant holding only the unconfigured row SSO's lock inserts has no
     * rule, and passes the question up.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantHoldingOnlyTheLocksRowPassesTheQuestionUp(): void
    {
        $this->rule(self::ROOT, true);

        DB::transaction(function (): void {
            $lock = $this->app?->make(EnforcementLock::class) ?? self::fail('The application has not booted.');

            self::assertFalse(EnforcementLock::isConfigured($lock->acquire(self::BRANCH)));
        });

        self::assertSame(1, TenantEnforcement::query()->where('tenant_id', self::BRANCH)->count());
        self::assertSame(self::ROOT, $this->enforcing(self::TENANT));
        self::assertSame(self::ROOT, $this->enforcing(self::BRANCH));
    }

    /**
     * Turning a tenant's own rule off under an ancestor whose rule is on, or an
     * inner ancestor's, leaves the tenants below it on the rule turned off,
     * which requires nothing, never on the outer ancestor's: a password sign-in
     * there signs in, a session the inner rule allowed still complies when its
     * tenant's subtree is judged again, and the outer ancestor still enforces
     * its own tenant.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testTurningAnInnerRuleOffUnderAnEnforcingAncestorLeavesNoSessionOutOfCompliance(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $this->rule(self::ROOT, true);
        $this->rule(self::REGION, true);
        $this->rule(self::TENANT, true);

        $hopper = $this->createPerson();

        $this->exemptions()->exempt(self::referenceOf($hopper));

        $allowed = $this->signedIn($this->signInWithPassword($hopper, self::BRANCH));

        $this->exemptions()->exemptNobody();

        $this->rule(self::TENANT, false);

        self::assertSame(self::TENANT, $this->enforcing(self::TENANT));
        self::assertFalse($this->policy(self::TENANT)->isRequired());

        $this->rule(self::REGION, false);

        self::assertSame(self::REGION, $this->enforcing(self::BRANCH));
        self::assertFalse($this->policy(self::BRANCH)->isRequired());

        $person = $this->createPerson();

        self::assertTrue($this->signInWithPassword($person, self::TENANT)->isSignedIn());
        self::assertTrue($this->signInWithPassword($person, self::BRANCH)->isSignedIn());
        self::assertSame(FailureReason::SSO_REQUIRED, $this->signInWithPassword($person, self::ROOT)->reason);

        $changes = $this->app?->make(SubtreePolicyChanges::class) ?? self::fail('The application has not booted.');

        self::assertSame(0, DB::transaction(static fn (): int => $changes->changed(self::REGION)));
        self::assertNull($this->stored($allowed)->getRevokedAt());
    }

    /**
     * SSO's own policy for a tenant names the enforcing ancestor, and its rule
     * and version, through the adapter.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSsosPolicyNamesTheEnforcingAncestor(): void
    {
        $version = $this->rule(self::REGION, true);
        $policy  = $this->app?->make(Enforcement::class)->policy(self::TENANT, self::GUARD) ?? self::fail('The application has not booted.');

        self::assertTrue($policy->isRequired());
        self::assertSame(self::REGION, $policy->enforcingTenantId);
        self::assertSame($version, $policy->version);
        self::assertSame([$this->connections[self::REGION]], $policy->connectionIds);
    }

    /**
     * Rows of `[ancestors]`: each answer a broken tree gives for the tests'
     * tenant.
     *
     * @return iterable<string, array{0: list<string>}>
     */
    public static function provideBrokenAncestries(): iterable
    {
        yield 'the tenant itself' => [[self::BRANCH, self::TENANT]];

        yield 'an ancestor twice' => [[self::BRANCH, self::REGION, self::BRANCH]];

        yield 'a blank ancestor' => [[self::BRANCH, ' ']];
    }

    /**
     * A tree whose ancestry has a cycle, or a blank id, is refused, never
     * followed.
     *
     * @param  list<string>  $ancestors
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideBrokenAncestries')]
    public function testABrokenTreeIsRefused(array $ancestors): void
    {
        $tree = \Mockery::mock(TenantTree::class);

        $tree->allows('ancestors')->with(self::TENANT)->andReturn($ancestors);

        $this->app?->instance(TenantTree::class, $tree);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('has a cycle or is broken');

        $this->enforcing(self::TENANT);
    }

    /**
     * With no tree configured by the time it is asked, the adapter throws
     * rather than stand the tenant alone; a tree that cannot be read throws its
     * failure.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNoTreeOrAnUnreadableTreeThrows(): void
    {
        $failure = new \RuntimeException('Unreadable.');

        $this->tree()->failFor(self::TENANT, $failure);

        try {
            $this->enforcing(self::TENANT);

            self::fail('An unreadable tree was answered.');
        } catch (\RuntimeException $exception) {
            self::assertSame($failure, $exception);
        }

        $this->app?->forgetInstance(TenantTree::class);
        $this->app?->offsetUnset(TenantTree::class);

        Config::set(TenancyContracts::TREE, null);

        $this->expectException(TenancyMisconfiguredException::class);

        $this->enforcing(self::TENANT);
    }

    /**
     * A password sign-in in a tenant whose ancestor's rule is on is refused as
     * `sso_required`; in the tree apart it signs in.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAPasswordSignInBelowAnEnforcingAncestorIsRefused(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $this->rule(self::ROOT, true);

        $person  = $this->createPerson();
        $refused = $this->signInWithPassword($person, self::TENANT);

        self::assertTrue($refused->isFailed());
        self::assertSame(FailureReason::SSO_REQUIRED, $refused->reason);
        self::assertTrue($this->signInWithPassword($person, self::APART)->isSignedIn());
    }

    /**
     * Turning an ancestor's rule on revokes, in its own transaction, the
     * sessions it no longer allows in that tenant and every tenant below it,
     * whatever `laravel-authentication`'s revocation switches say, and keeps an
     * exempt person's, every session in the tree apart, and every one in a
     * tenant nearer that enforces a rule it still meets; turning it off again
     * revokes nothing.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAnAncestorsRuleChangeRevokesThroughItsSubtree(?string $level): void
    {
        self::runAtIsolationLevel($level);

        Config::set('authentication.revocation.connection_disabled', false);
        Config::set('authentication.revocation.connection_deleted', false);
        Config::set('authentication.revocation.link_removed', false);

        [$ada, $grace, $hopper] = [$this->createPerson(), $this->createPerson(), $this->createPerson()];

        $revoked = [
            $this->signedIn($this->signInWithPassword($ada, self::REGION)),
            $this->signedIn($this->signInWithPassword($ada, self::BRANCH)),
            $this->signedIn($this->signInWithPassword($grace, self::TENANT)),
        ];
        $exempt = $this->signedIn($this->signInWithPassword($hopper, self::TENANT));
        $kept   = [$this->signedIn($this->signInWithPassword($ada, self::ROOT)), $this->signedIn($this->signInWithPassword($grace, self::APART))];

        $this->exemptions()->exempt(self::referenceOf($hopper));

        $this->rule(self::REGION, true);

        foreach ($revoked as $session) {
            self::assertNotNull($this->stored($session)->getRevokedAt(), (string) $session->getTenantId());
        }

        foreach ([$exempt, ...$kept] as $session) {
            self::assertNull($this->stored($session)->getRevokedAt(), (string) $session->getTenantId());
        }

        $this->rule(self::REGION, false);

        foreach ([$exempt, ...$kept] as $session) {
            self::assertNull($this->stored($session)->getRevokedAt(), (string) $session->getTenantId());
        }

        Event::assertDispatchedTimes(EnforcementChanged::class, 2);
    }

    /**
     * The tenant SSO's enforcement inheritance names for the tenant, as SSO
     * asks it.
     *
     * @param  string  $tenantId
     * @return string
     *
     * @phpstan-impure
     */
    private function enforcing(string $tenantId): string
    {
        $inheritance = $this->app?->make(EnforcementInheritance::class) ?? self::fail('The application has not booted.');

        return $inheritance->enforcingTenant($tenantId, self::GUARD);
    }

    /**
     * SSO's own policy for a tenant, through the adapter.
     *
     * @param  string  $tenantId
     * @return \SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy
     */
    private function policy(string $tenantId): EnforcementPolicy
    {
        $enforcement = $this->app?->make(Enforcement::class) ?? self::fail('The application has not booted.');

        return $enforcement->policy($tenantId, self::GUARD);
    }

    /**
     * Turn the tenant's rule on, satisfied by a connection of its own, made
     * once and marked as having completed a sign-in, or off; answer the version
     * stored.
     *
     * @param  string  $tenantId
     * @param  bool  $on
     * @return ?string
     */
    private function rule(string $tenantId, bool $on): ?string
    {
        $connection = $this->connections[$tenantId] ??= $this->makeConnection($tenantId);

        DB::table('sso_connections')->where('id', $connection)->update(['has_completed_sign_in' => true]);

        $service = $this->app?->make(EnforcementService::class) ?? self::fail('The application has not booted.');
        $result  = $service->update($tenantId, $on, $on ? [$connection] : [], self::ssoClient());

        self::assertTrue($result->isChanged(), sprintf('The enforcement did not change: [%s].', $result->reason->value ?? $result->status->value));

        return $result->enforcement?->version;
    }

    /**
     * Sign the person in with their password, asking to act in the tenant.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  string  $tenantId
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    private function signInWithPassword(Person $person, string $tenantId): SignInResult
    {
        $context = new SignInContext(self::client(), tenant: TenantSelection::of($tenantId));

        return $this->sessions()->signIn('password', ['email' => $person->email, 'password' => self::PASSWORD], $context);
    }

    /**
     * The session the sign-in established, failing unless it is active.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInResult  $answer
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession
     */
    private function signedIn(SignInResult $answer): EloquentSession&Model
    {
        self::assertTrue($answer->isSignedIn(), (string) $answer->reason?->value);

        return $answer->session->record ?? self::fail('The sign-in established no session.');
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
     * What the container resolves the abstract to.
     *
     * @param  string  $abstract
     * @return mixed
     */
    private function resolved(string $abstract): mixed
    {
        return $this->app?->make($abstract);
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
     * The application's break-glass rule.
     *
     * @return \Tests\Fixtures\Tenancy\ExemptsIdentities
     */
    private function exemptions(): ExemptsIdentities
    {
        return $this->exemptions ?? self::fail('The exemptions are not arranged.');
    }
}
