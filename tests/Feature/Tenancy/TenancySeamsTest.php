<?php

declare(strict_types = 1);

namespace Tests\Feature\Tenancy;

use Illuminate\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Tenancy\RequireNothingOfTenants;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Iam\Authorization\GrantScopeAdapter;
use SineMacula\Laravel\Iam\Bindings\Enums\Lifetime;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Iam\IamServiceProvider;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use SineMacula\Laravel\Iam\Sso\SsoSeams;
use SineMacula\Laravel\Iam\Tenancy\Contracts\GrantScope;
use SineMacula\Laravel\Iam\Tenancy\EnforcementInheritanceAdapter;
use SineMacula\Laravel\Iam\Tenancy\LinkEligibilityAdapter;
use SineMacula\Laravel\Iam\Tenancy\PrincipalScopeAdapter;
use SineMacula\Laravel\Iam\Tenancy\TenancyContracts;
use SineMacula\Laravel\Iam\Tenancy\TenancySeams;
use SineMacula\Laravel\Iam\Tenancy\TenantAuthenticationPolicyAdapter;
use SineMacula\Laravel\Iam\Tenancy\TenantMembershipAdapter;
use SineMacula\Laravel\Iam\Testing\FakeMemberships;
use SineMacula\Laravel\Sso\Contracts\EnforcementInheritance;
use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Contracts\PrincipalScope;
use SineMacula\Laravel\Sso\Contracts\TenantMembership;
use SineMacula\Laravel\Sso\Enforcement\OwnTenantInheritance;
use SineMacula\Laravel\Sso\Linking\NoTenantMembership;
use SineMacula\Laravel\Sso\Linking\RefusingLinkEligibility;
use SineMacula\Laravel\Sso\Linking\RefusingPrincipalScope;
use Tests\Fixtures\Providers\BindsTenancyWhileBooting;
use Tests\Fixtures\Providers\BindsTenancyWhileRegistering;
use Tests\Fixtures\Tenancy\ScriptedTenantRequirement;
use Tests\Fixtures\Tenancy\StoredTenantTree;
use Tests\TestCase;

/**
 * Feature tests for the seams answered from the application's tenancy.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TenancySeams::class)]
#[CoversClass(TenancyContracts::class)]
#[CoversClass(IamServiceProvider::class)]
final class TenancySeamsTest extends TestCase
{
    /**
     * The policy adapter is bound over `laravel-authentication`'s default.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testThePolicyAdapterIsBoundOverTheDefault(): void
    {
        self::assertInstanceOf(TenantAuthenticationPolicyAdapter::class, $this->resolved(TenantAuthenticationPolicy::class));
    }

    /**
     * With SSO's switch off nothing is bound.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[WithConfig(MfaSeams::SWITCH, true, defer: false)]
    #[WithConfig(SsoSeams::SWITCH, false, defer: false)]
    public function testTheSsoSwitchOffBindsNothing(): void
    {
        ScriptedTenantRequirement::bind($this->app);

        self::assertInstanceOf(RequireNothingOfTenants::class, $this->resolved(TenantAuthenticationPolicy::class));
        self::assertInstanceOf(NoTenantMembership::class, $this->resolved(TenantMembership::class));
        self::assertInstanceOf(OwnTenantInheritance::class, $this->resolved(EnforcementInheritance::class));
    }

    /**
     * Rows of `[configuration, mandatory]`.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: bool}>
     */
    public static function provideMandates(): iterable
    {
        yield 'neither' => [[], false];

        yield 'enforcement off' => [[TenancySeams::ENFORCEMENT => false], false];

        yield 'enforcement on' => [[TenancySeams::ENFORCEMENT => true], true];

        yield 'enforcement on, as an environment variable fills it' => [[TenancySeams::ENFORCEMENT => 'true'], true];
    }

    /**
     * The policy is mandatory while SSO enforces.
     *
     * @param  array<string, mixed>  $values
     * @param  bool  $mandatory
     * @return void
     */
    #[DataProvider('provideMandates')]
    public function testTheBindingIsMandatoryWhileEnforcementIsOn(array $values, bool $mandatory): void
    {
        $config    = new Repository;
        $container = $this->container();

        foreach ($values as $key => $value) {
            $config->set($key, $value);
        }

        self::assertSame($mandatory, (new TenancySeams($container))->seams($config)[0]->isMandatory());
    }

    /**
     * A bound tenant requirement makes the policy mandatory.
     *
     * @return void
     */
    public function testARequirementBoundMakesTheBindingMandatory(): void
    {
        $container = $this->container();
        $binding   = (new TenancySeams($container))->seams(new Repository)[0];

        self::assertFalse($binding->isMandatory());

        ScriptedTenantRequirement::bind($container);

        self::assertTrue($binding->isMandatory());
    }

    /**
     * Without memberships SSO's membership defaults stay.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testWithoutMembershipsSsosMembershipDefaultsStay(): void
    {
        self::assertInstanceOf(NoTenantMembership::class, $this->resolved(TenantMembership::class));
        self::assertInstanceOf(RefusingLinkEligibility::class, $this->resolved(LinkEligibility::class));
        self::assertInstanceOf(RefusingPrincipalScope::class, $this->resolved(PrincipalScope::class));
        self::assertInstanceOf(EnforcementInheritanceAdapter::class, $this->resolved(EnforcementInheritance::class));
    }

    /**
     * Memberships bound in `register()` bind the membership adapters.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testMembershipsBoundWhileRegisteringBindTheMembershipAdapters(): void
    {
        $this->reorderProviders([...self::MEMBER_PROVIDERS, IamServiceProvider::class, BindsTenancyWhileRegistering::class]);

        self::assertInstanceOf(TenantMembershipAdapter::class, $this->resolved(TenantMembership::class));
        self::assertInstanceOf(LinkEligibilityAdapter::class, $this->resolved(LinkEligibility::class));
        self::assertInstanceOf(PrincipalScopeAdapter::class, $this->resolved(PrincipalScope::class));
    }

    /**
     * Memberships bound only from a `boot()` bind nothing.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testMembershipsBoundWhileBootingBindNothing(): void
    {
        $this->reorderProviders([...self::MEMBER_PROVIDERS, IamServiceProvider::class, BindsTenancyWhileBooting::class]);

        self::assertInstanceOf(NoTenantMembership::class, $this->resolved(TenantMembership::class));
    }

    /**
     * The inheritance is mandatory while SSO enforces over a tenant tree.
     *
     * @return void
     */
    public function testTheInheritanceIsMandatoryWhileEnforcingOverATree(): void
    {
        $config  = new Repository;
        $binding = (new TenancySeams($this->container()))->seams($config)[4];

        self::assertFalse($binding->isMandatory());

        $config->set(TenancySeams::ENFORCEMENT, true);

        self::assertFalse($binding->isMandatory());

        $this->app?->instance(TenantTree::class, new StoredTenantTree);

        self::assertTrue($binding->isMandatory());

        $config->set(TenancySeams::ENFORCEMENT, false);

        self::assertFalse($binding->isMandatory());
    }

    /**
     * Rows of `[sso, memberships bound, memberships on, inheritance on]`.
     *
     * @return iterable<string, array{0: mixed, 1: bool, 2: bool, 3: bool}>
     */
    public static function provideTenancyRows(): iterable
    {
        yield 'nothing' => [true, false, false, true];

        yield 'memberships bound' => [true, true, true, true];

        yield 'sso off' => ['off', true, false, false];
    }

    /**
     * The tenancy rows follow SSO's switch and the application's tenancy.
     *
     * @param  mixed  $sso
     * @param  bool  $membershipsBound
     * @param  bool  $membershipsOn
     * @param  bool  $inheritanceOn
     * @return void
     */
    #[DataProvider('provideTenancyRows')]
    public function testTheTenancyRowsFollowTheSwitchAndTheApplicationsTenancy(mixed $sso, bool $membershipsBound, bool $membershipsOn, bool $inheritanceOn): void
    {
        $container = $this->container();
        $config    = new Repository(['iam' => ['adapters' => ['sso' => $sso]]]);

        if ($membershipsBound) {
            FakeMemberships::fake($container);
        }

        $bindings = (new TenancySeams($container))->seams($config);

        foreach (array_slice($bindings, 1, 3) as $binding) {
            self::assertSame($membershipsOn, $binding->on, $binding->abstract);
        }

        self::assertSame($inheritanceOn, $bindings[4]->on);
        self::assertSame($inheritanceOn, $bindings[0]->on);
    }

    /**
     * Every row is transient; only policy and inheritance carry a mandate.
     *
     * @return void
     */
    public function testEveryRowIsTransientAndOptionalWithoutATenantsRule(): void
    {
        $rows = array_map(
            static fn (SeamBinding $binding): array => [$binding->abstract, $binding->adapter, $binding->lifetime, $binding->isMandatory()],
            (new TenancySeams($this->container()))->seams(new Repository),
        );

        self::assertSame([
            [TenantAuthenticationPolicy::class, TenantAuthenticationPolicyAdapter::class, Lifetime::TRANSIENT, false],
            [TenantMembership::class, TenantMembershipAdapter::class, Lifetime::TRANSIENT, false],
            [LinkEligibility::class, LinkEligibilityAdapter::class, Lifetime::TRANSIENT, false],
            [PrincipalScope::class, PrincipalScopeAdapter::class, Lifetime::TRANSIENT, false],
            [EnforcementInheritance::class, EnforcementInheritanceAdapter::class, Lifetime::TRANSIENT, false],
        ], $rows);
    }

    /**
     * The grant scope is authorization's query, built per resolution.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheGrantScopeIsAuthorizationsQuery(): void
    {
        $scope = $this->resolved(GrantScope::class);

        self::assertInstanceOf(GrantScopeAdapter::class, $scope);
        self::assertNotSame($scope, $this->resolved(GrantScope::class));
    }

    /**
     * What the container resolves the abstract to.
     *
     * @param  string  $abstract
     * @return mixed
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function resolved(string $abstract): mixed
    {
        return $this->app?->make($abstract);
    }

    /**
     * The application's container, MFA's tenant requirement as MFA bound it.
     *
     * @return \Illuminate\Contracts\Foundation\Application
     */
    private function container(): Application
    {
        return $this->app ?? self::fail('The application has not booted.');
    }
}
