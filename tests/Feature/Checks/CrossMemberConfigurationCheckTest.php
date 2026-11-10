<?php

declare(strict_types = 1);

namespace Tests\Feature\Checks;

use Illuminate\Contracts\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Tenancy\ResolveNoTenant;
use SineMacula\Laravel\Iam\Audit\AuditSettings;
use SineMacula\Laravel\Iam\Audit\CaptureExclusions;
use SineMacula\Laravel\Iam\Checks\AuditCheck;
use SineMacula\Laravel\Iam\Checks\CrossMemberConfigurationCheck;
use SineMacula\Laravel\Iam\Checks\SeamHolders;
use SineMacula\Laravel\Iam\Checks\Sso\SsoBridgeCheck;
use SineMacula\Laravel\Iam\Checks\StorageCheck;
use SineMacula\Laravel\Iam\Contracts\TenantMfaRequirement;
use SineMacula\Laravel\Iam\Tenancy\TenancySeams;
use SineMacula\Laravel\Iam\Testing\FakeTenantMfaRequirement;
use SineMacula\Laravel\Mfa\Enums\Operation;
use SineMacula\Laravel\Sso\Config\Checks\EndpointsCheck;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use Tests\Concerns\RunsChecks;
use Tests\Fixtures\Resolvers\OpenTenancy;
use Tests\Fixtures\Tenancy\StoredTenantTree;
use Tests\TestCase;

/**
 * Feature tests for the configuration that crosses the members (IAM-2.5),
 * bullet by bullet: the ones this check holds (MFA's applications, the members'
 * freshness operations and the tenant resolver a tenant's rule needs), and the
 * ones held where they belong, SSO's by the check SSO's own runs and
 * audit-log's by the audit check, so every bullet is pinned here.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CrossMemberConfigurationCheck::class)]
final class CrossMemberConfigurationCheckTest extends TestCase
{
    use RunsChecks;

    /** @var string Why MFA's operations undeclared for the guard the tests sign in on are refused. */
    private const string UNDECLARED = 'MFA\'s freshness operations [%s] are not declared for guard [api] under `authentication.freshness` or the guard\'s `freshness`.';

    /** @var string Why a tenant resolver still on `laravel-authentication`'s default is refused. */
    private const string NO_TENANT_RESOLVER = 'SineMacula\Laravel\Authentication\Contracts\TenantResolver is still bound to'
        . ' SineMacula\Laravel\Authentication\Tenancy\ResolveNoTenant while SSO\'s enforcement is on or a tenant MFA requirement is named:'
        . ' bind a resolver that resolves every tenant id to the tenant whose `getTenantIdentifier()` is that id.';

    /**
     * MFA's operations, undeclared under `laravel-authentication`'s freshness
     * as it ships, are refused for the MFA application's guard; declared, they
     * pass.
     *
     * @return void
     */
    public function testMfasOperationsMustBeDeclared(): void
    {
        $operations = 'mfa.add_factor, mfa.replace_factor, mfa.remove_factor, mfa.generate_recovery_codes';

        self::assertSame([sprintf(self::UNDECLARED, $operations)], self::problems($this->check()->checks()));

        $this->declare(array_column(Operation::cases(), 'value'));

        self::assertSame([], self::problems($this->check()->checks()));
        self::assertTrue($this->check()->applies());
        self::assertSame('configuration', $this->check()->subject());
    }

    /**
     * An operation is declared by the guard's own freshness block too, and
     * removed there by `null`.
     *
     * @return void
     */
    public function testTheGuardsOwnBlockDeclaresAndRemoves(): void
    {
        $config = $this->app?->make('config');

        $this->declare(['mfa.add_factor', 'mfa.replace_factor', 'mfa.remove_factor']);

        $config?->set('auth.guards.api.freshness', ['mfa.generate_recovery_codes' => ['max_age_seconds' => 300, 'proofs' => ['additional_factor']], 'mfa.add_factor' => null]);

        self::assertSame([sprintf(self::UNDECLARED, 'mfa.add_factor')], self::problems($this->check()->checks()));

        $config?->set('auth.guards.api.freshness', 'not a block');
        $config?->set('authentication.freshness', 'not a block');

        self::assertCount(1, self::problems($this->check()->checks()));
    }

    /**
     * Every MFA application must name a guard: MFA's application is the guard
     * of the same name, one listed rather than named included.
     *
     * @return void
     */
    public function testEveryMfaApplicationMustBeAGuard(): void
    {
        $this->declare(array_column(Operation::cases(), 'value'));

        $this->app?->make('config')->set('mfa.applications.admin', ['types' => ['totp']]);

        self::assertSame(['`mfa.applications.admin` names no guard in `auth.guards`: MFA\'s application is the guard of the same name.'], self::problems($this->check()->checks()));

        $this->app?->make('config')->set('mfa.applications', [['types' => ['totp']]]);

        self::assertSame(['`mfa.applications.0` names no guard in `auth.guards`: MFA\'s application is the guard of the same name.'], self::problems($this->check()->checks()));
    }

    /**
     * An MFA application on a guard of another driver than `jwt`, which holds
     * no session for MFA to act on, is refused at deploy, whatever its other
     * driver or none, rather than by every MFA call at runtime; on a `jwt`
     * guard it passes.
     *
     * @return void
     */
    public function testEveryMfaApplicationMustBeAJwtGuard(): void
    {
        $config  = $this->app?->make('config');
        $refusal = '`mfa.applications.machines` names a guard in `auth.guards` whose driver is not `jwt`: MFA\'s application is a guard that holds sessions.';

        $this->declare(array_column(Operation::cases(), 'value'));

        $config?->set('mfa.applications.machines', ['types' => ['totp']]);

        foreach ([['driver' => 'api_key', 'provider' => 'people'], ['driver' => 'session'], ['provider' => 'people']] as $guard) {
            $config?->set('auth.guards.machines', $guard);

            self::assertSame([$refusal], self::problems($this->check()->checks()));
        }

        $config?->set('auth.guards.machines', ['driver' => 'jwt', 'provider' => 'people']);

        self::assertSame([], self::problems($this->check()->checks()));
    }

    /**
     * With no MFA application and SSO out of use, nothing is required.
     *
     * @return void
     */
    public function testNoApplicationsRequireNothing(): void
    {
        $this->app?->make('config')->set('mfa.applications', null);

        self::assertSame([], $this->check()->checks());
    }

    /**
     * Rows of how a tenant's rule comes to reach a session: a tenant MFA
     * requirement named, one bound, and SSO's enforcement turned on.
     *
     * @return iterable<string, array{0: \Closure(\Illuminate\Contracts\Foundation\Application): void}>
     */
    public static function provideTenantRules(): iterable
    {
        yield 'a requirement named' => [static function (Application $app): void {
            $app->make('config')->set('iam.tenancy.mfa_requirement', FakeTenantMfaRequirement::class);
        }];

        yield 'a requirement bound' => [static function (Application $app): void {
            $app->bind(TenantMfaRequirement::class, FakeTenantMfaRequirement::class);
        }];

        yield 'SSO\'s enforcement on' => [static function (Application $app): void {
            $app->make('config')->set(TenancySeams::ENFORCEMENT, true);
        }];
    }

    /**
     * While a tenant's rule reaches a session, `laravel-authentication`'s
     * tenant resolver left on its `ResolveNoTenant` is refused, since MFA's
     * tenant requirement, the tree's changes and SSO's revocation resolve the
     * session's tenant through it; a resolver of the application's own, as an
     * instance, a class name or a closure, passes.
     *
     * @param  \Closure(\Illuminate\Contracts\Foundation\Application): void  $rule
     * @return void
     */
    #[DataProvider('provideTenantRules')]
    public function testTheTenantResolverMustResolveWhileATenantsRuleReachesASession(\Closure $rule): void
    {
        $app = $this->app;

        assert($app instanceof Application);

        $this->declare(array_column(Operation::cases(), 'value'));

        $rule($app);

        self::assertSame([self::NO_TENANT_RESOLVER], self::problems($this->check()->checks()));

        $app->instance(TenantResolver::class, new OpenTenancy);

        self::assertSame([], self::problems($this->check()->checks()));

        $app->singleton(TenantResolver::class, OpenTenancy::class);

        self::assertSame([], self::problems($this->check()->checks()));

        $app->singleton(TenantResolver::class, static fn (): TenantResolver => new OpenTenancy);

        self::assertSame([], self::problems($this->check()->checks()));
    }

    /**
     * With no tenant MFA requirement and SSO's enforcement off, no tenant's
     * rule reaches a session, so `ResolveNoTenant` is the application's choice,
     * even with a tenant tree named, whose changes then resolve nothing.
     *
     * @return void
     */
    public function testNoTenantsRuleRequiresNoResolver(): void
    {
        $config = $this->app?->make('config');

        $this->declare(array_column(Operation::cases(), 'value'));

        $config?->set('iam.tenancy.tree', StoredTenantTree::class);
        $config?->set(TenancySeams::ENFORCEMENT, false);

        self::assertSame(ResolveNoTenant::class, $this->app?->make(SeamHolders::class)->of($this->app, TenantResolver::class));
        self::assertSame([], self::problems($this->check()->checks()));
    }

    /**
     * While SSO is in use, SSO's operations must be declared for each SSO
     * application's guard; out of use, they are not required.
     *
     * @return void
     */
    public function testSsosOperationsMustBeDeclaredWhileSsoIsInUse(): void
    {
        $config = $this->app?->make('config');

        $this->declare(array_column(Operation::cases(), 'value'));

        $config?->set('sso.applications', ['api' => []]);

        self::assertSame([], self::problems($this->check()->checks()));

        $config?->set('sso.features.saml2', true);

        $problems = self::problems($this->check()->checks());

        self::assertCount(1, $problems);
        self::assertStringStartsWith('SSO\'s freshness operations [sso.connection.trust, ', $problems[0]);

        $this->declare([...array_column(Operation::cases(), 'value'), ...array_column(FreshnessOperation::cases(), 'value')]);

        self::assertSame([], self::problems($this->check()->checks()));
    }

    /**
     * `laravel-authentication`'s side is the tenant resolver, about no one
     * guard, and the MFA and SSO applications named after a guard, about that
     * guard, the SSO application's only while SSO is in use.
     *
     * @return void
     */
    public function testLaravelAuthenticationsSideIsTheTenantResolverAndEachGuardsApplications(): void
    {
        $config = $this->app?->make('config');

        $config?->set('sso.applications', ['api' => [], 'portal' => []]);

        self::assertSame([], $this->check()->authenticationChecks());
        $undeclared = 'mfa.add_factor, mfa.replace_factor, mfa.remove_factor, mfa.generate_recovery_codes';

        self::assertSame([sprintf(self::UNDECLARED, $undeclared)], self::problems($this->check()->guardChecks('api')));
        self::assertCount(2, $this->check()->guardChecks('api'));
        self::assertSame([], $this->check()->guardChecks('portal'));

        $config?->set('sso.features.saml2', true);
        $this->app?->bind(TenantMfaRequirement::class, FakeTenantMfaRequirement::class);

        self::assertSame([self::NO_TENANT_RESOLVER], self::problems($this->check()->authenticationChecks()));
        self::assertCount(3, $this->check()->guardChecks('api'));
        self::assertCount(1, $this->check()->guardChecks('portal'));
        self::assertSame([], $this->check()->guardChecks('other'));
    }

    /**
     * SSO's bullets are each held once: every application SSO serves allowing
     * `external_provider` and none handing off an unlinked result by the check
     * SSO's own runs; the base URL set by SSO's own endpoints check, which
     * `sso:check` runs too; and the storage connection the shared one by the
     * storage check.
     *
     * @return void
     */
    public function testSsosBulletsAreHeldBySsosCheck(): void
    {
        $config = $this->app?->make('config');

        $config?->set('sso.features.saml2', true);
        $config?->set('sso.applications', ['api' => ['unlinked_handoffs' => true]]);
        $config?->set('sso.endpoints.base_url', null);

        self::assertSame([
            '`sso.applications.api` is served by SSO, but its guard does not list `external_provider` among laravel-authentication\'s sign-in methods.',
            '`sso.applications.api.unlinked_handoffs` must stay off under laravel-iam: an unlinked result is provisioned or refused, never handed off.',
        ], self::problems($this->bridge()->checks()));

        $endpoints = $this->app?->make(EndpointsCheck::class);

        assert($endpoints instanceof EndpointsCheck);

        self::assertStringStartsWith('`sso.endpoints.base_url` must be', self::problems($endpoints->checks())[0]);

        $config?->set('database.connections.elsewhere', ['driver' => 'sqlite', 'database' => ':memory:']);
        $config?->set('sso.storage.connection', 'elsewhere');

        $storage = $this->app->make(StorageCheck::class);

        self::assertCount(1, array_filter(self::problems($storage->checks()), static fn (string $problem): bool => str_contains($problem, 'sso.storage.connection')));
        self::assertSame([], array_filter(self::problems($this->bridge()->checks()), static fn (string $problem): bool => str_contains($problem, 'sso.')
            && !str_contains($problem, 'sso.applications')));
    }

    /**
     * Audit-log's bullets are held by the audit check: every `jwt` and
     * `api_key` guard excluded from its capture, its Gate capture off and its
     * refusal of unregistered codes on.
     *
     * @return void
     */
    public function testAuditLogsBulletsAreHeldByTheAuditCheck(): void
    {
        $config = $this->app?->make('config');

        $config?->set(CaptureExclusions::GATE_KEY, true);

        self::assertCount(3, self::problems($this->audit()->checks()));

        $config?->set(CaptureExclusions::EXCEPT_GUARDS_KEY, ['*']);
        $config?->set(CaptureExclusions::GATE_KEY, false);
        $config?->set(AuditSettings::REQUIRE_REGISTERED, true);

        self::assertSame([], self::problems($this->audit()->checks()));
    }

    /**
     * Declare the operations under `laravel-authentication`'s freshness, the
     * shipped ones kept.
     *
     * @param  list<string>  $operations
     * @return void
     */
    private function declare(array $operations): void
    {
        $config = $this->app?->make('config');

        /** @var array<string, mixed> $freshness */
        $freshness = $config?->get('authentication.freshness');

        foreach ($operations as $operation) {
            $freshness[$operation] = ['max_age_seconds' => 900, 'proofs' => ['additional_factor']];
        }

        $config?->set('authentication.freshness', $freshness);
    }

    /**
     * The check, resolved as `iam:check` resolves it.
     *
     * @return \SineMacula\Laravel\Iam\Checks\CrossMemberConfigurationCheck
     */
    private function check(): CrossMemberConfigurationCheck
    {
        $check = $this->app?->make(CrossMemberConfigurationCheck::class);

        assert($check instanceof CrossMemberConfigurationCheck);

        return $check;
    }

    /**
     * The check SSO's own runs for this package.
     *
     * @return \SineMacula\Laravel\Iam\Checks\Sso\SsoBridgeCheck
     */
    private function bridge(): SsoBridgeCheck
    {
        $check = $this->app?->make(SsoBridgeCheck::class);

        assert($check instanceof SsoBridgeCheck);

        return $check;
    }

    /**
     * The audit check.
     *
     * @return \SineMacula\Laravel\Iam\Checks\AuditCheck
     */
    private function audit(): AuditCheck
    {
        $check = $this->app?->make(AuditCheck::class);

        assert($check instanceof AuditCheck);

        return $check;
    }
}
