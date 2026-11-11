<?php

declare(strict_types = 1);

namespace Tests\Feature\Tenancy;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Contracts\Container\Container as ContainerContract;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Tenancy\RequireNothingOfTenants;
use SineMacula\Laravel\Iam\Authorization\GrantScopeAdapter;
use SineMacula\Laravel\Iam\Bindings\BindingOutcome;
use SineMacula\Laravel\Iam\Bindings\BindingRule;
use SineMacula\Laravel\Iam\Bindings\Enums\Lifetime;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Iam\Contracts\Memberships;
use SineMacula\Laravel\Iam\Contracts\TenantTree;
use SineMacula\Laravel\Iam\IamServiceProvider;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use SineMacula\Laravel\Iam\Sso\SessionRevocationAdapter;
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
use SineMacula\Laravel\Iam\Testing\FakeTenantTree;
use SineMacula\Laravel\Mfa\Contracts\TenantRequirement;
use SineMacula\Laravel\Mfa\Requirements\NoTenantRequirement;
use SineMacula\Laravel\Sso\Contracts\EnforcementInheritance;
use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Contracts\PrincipalScope;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Contracts\TenantMembership;
use SineMacula\Laravel\Sso\Enforcement\OwnTenantInheritance;
use SineMacula\Laravel\Sso\Linking\NoTenantMembership;
use SineMacula\Laravel\Sso\Linking\RefusingLinkEligibility;
use SineMacula\Laravel\Sso\Linking\RefusingPrincipalScope;
use Tests\Concerns\PermutesProviderOrder;
use Tests\Fixtures\Providers\BindsTenancyWhileBooting;
use Tests\Fixtures\Providers\BindsTenancyWhileRegistering;
use Tests\Fixtures\Providers\TurnsSsoOffWhileRegistering;
use Tests\Fixtures\Providers\TurnsSsoOnWhileRegistering;
use Tests\Fixtures\Tenancy\ScriptedTenantRequirement;
use Tests\TestCase;

/**
 * Feature tests for the seam the tenants' authentication policy is answered
 * through (IAM-4.5): the composite adapter replaces `laravel-authentication`'s
 * default in every provider order; an application's own binding is kept or wins
 * as the binding rule says (IAM-8.4); it is bound while the SSO capability's
 * switch is on, whatever MFA's, and not while it is off, MFA's on or not; and
 * it is mandatory while SSO's enforcement is on or the application binds MFA's
 * tenant requirement off MFA's default. SSO's tenant membership, link
 * eligibility and principal scope are bound while the switch is on and the
 * application names or binds its memberships by the time every provider has
 * registered (in its own provider's `register()`, which Laravel runs after the
 * packages', included),
 * and SSO's enforcement inheritance while it names or binds a tenant tree;
 * otherwise, or once they are bound only from a `boot()`, SSO's defaults stay,
 * and the application's own bindings are kept. The grant half of the principal
 * scope is `GrantScopeAdapter` while `iam.adapters.authorization` is on, and
 * `UnknownGrantScope` while it is off, until something else is bound.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TenancySeams::class)]
#[CoversClass(TenancyContracts::class)]
#[CoversClass(IamServiceProvider::class)]
#[CoversClass(BindingRule::class)]
final class TenancySeamsTest extends TestCase
{
    use PermutesProviderOrder;

    /**
     * The adapter is bound over `laravel-authentication`'s default in every
     * provider order.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testTheAdapterIsBoundOverTheDefaultInEveryProviderOrder(array $providers): void
    {
        $this->bootInOrder($providers);

        self::assertInstanceOf(TenantAuthenticationPolicyAdapter::class, $this->resolved(TenantAuthenticationPolicy::class));
        $this->assertOutcome(true);
    }

    /**
     * An application binding made before any provider registers is kept, in
     * every provider order.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testAnApplicationBindingMadeBeforeAnyProviderRegistersIsKept(array $providers): void
    {
        $policy = \Mockery::mock(TenantAuthenticationPolicy::class);

        $this->bootInOrder($providers, before: [TenantAuthenticationPolicy::class => static fn (): object => $policy]);

        self::assertSame($policy, $this->resolved(TenantAuthenticationPolicy::class));
        $this->assertOutcome(false);
    }

    /**
     * An application binding made once every provider has registered replaces
     * the adapter, in every provider order.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testAnApplicationBindingMadeOnceEveryProviderHasRegisteredWins(array $providers): void
    {
        $policy = \Mockery::mock(TenantAuthenticationPolicy::class);

        $this->bootInOrder($providers, after: [TenantAuthenticationPolicy::class => static fn (): object => $policy]);

        self::assertSame($policy, $this->resolved(TenantAuthenticationPolicy::class));
        $this->assertOutcome(true);
    }

    /**
     * With both capabilities' switches off, nothing is bound and
     * `laravel-authentication`'s default stays.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[WithConfig(MfaSeams::SWITCH, false, defer: false)]
    #[WithConfig(SsoSeams::SWITCH, false, defer: false)]
    public function testBothSwitchesOffBindNothing(): void
    {
        self::assertInstanceOf(RequireNothingOfTenants::class, $this->resolved(TenantAuthenticationPolicy::class));

        $outcome = $this->resolved(BindingOutcome::class);

        self::assertInstanceOf(BindingOutcome::class, $outcome);
        self::assertNotContains(TenantAuthenticationPolicy::class, [...$outcome->bound, ...$outcome->kept]);
    }

    /**
     * With MFA's switch on and SSO's off, nothing is bound and
     * `laravel-authentication`'s default stays, MFA's tenant requirement bound
     * or not: the adapter would find no sign-in's connection, which only the
     * SSO capability records, so the policy is the application's to bind.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[WithConfig(MfaSeams::SWITCH, true, defer: false)]
    #[WithConfig(SsoSeams::SWITCH, false, defer: false)]
    public function testMfaOnWithSsoOffBindsNothing(): void
    {
        ScriptedTenantRequirement::bind($this->app);

        self::assertInstanceOf(RequireNothingOfTenants::class, $this->resolved(TenantAuthenticationPolicy::class));

        $outcome = $this->resolved(BindingOutcome::class);

        self::assertInstanceOf(BindingOutcome::class, $outcome);
        self::assertNotContains(TenantAuthenticationPolicy::class, [...$outcome->bound, ...$outcome->kept]);
    }

    /**
     * Rows of `[mfa, sso, on]`: each capability's switch, and whether the
     * binding is on.
     *
     * @return iterable<string, array{0: mixed, 1: mixed, 2: bool}>
     */
    public static function provideSwitches(): iterable
    {
        yield 'both on' => [true, true, true];

        yield 'only mfa on' => [true, 'off', false];

        yield 'only sso on' => ['0', null, true];

        yield 'both off' => [false, 'no', false];
    }

    /**
     * The binding is on while the SSO capability's switch is, whatever MFA's,
     * each read leniently.
     *
     * @param  mixed  $mfa
     * @param  mixed  $sso
     * @param  bool  $on
     * @return void
     */
    #[DataProvider('provideSwitches')]
    public function testTheBindingIsOnWhileTheSsoSwitchIs(mixed $mfa, mixed $sso, bool $on): void
    {
        $config = new Repository(['iam' => ['adapters' => ['mfa' => $mfa, 'sso' => $sso]]]);

        [$binding] = (new TenancySeams(new Container))->seams($config);

        self::assertNotNull($binding->appliesWhen);
        self::assertSame($on, ($binding->appliesWhen)($config));
    }

    /**
     * The binding is transient over `laravel-authentication`'s default.
     *
     * @return void
     */
    public function testTheBindingIsTransientOverTheDefault(): void
    {
        $bindings = (new TenancySeams(new Container))->seams(new Repository);

        self::assertCount(5, $bindings);
        self::assertSame(TenantAuthenticationPolicy::class, $bindings[0]->abstract);
        self::assertSame(TenantAuthenticationPolicyAdapter::class, $bindings[0]->adapter);
        self::assertSame([RequireNothingOfTenants::class], $bindings[0]->memberDefaults);
        self::assertSame(Lifetime::TRANSIENT, $bindings[0]->lifetime);
    }

    /**
     * Rows of `[configuration, mandatory]`: SSO's enforcement as configured,
     * and whether the binding is mandatory.
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
     * With MFA's default tenant requirement, the binding is mandatory while
     * SSO's enforcement is on.
     *
     * @param  array<string, mixed>  $values
     * @param  bool  $mandatory
     * @return void
     */
    #[DataProvider('provideMandates')]
    public function testTheBindingIsMandatoryWhileEnforcementIsOn(array $values, bool $mandatory): void
    {
        $config    = new Repository;
        $container = self::container();

        $container->bind(TenantRequirement::class, NoTenantRequirement::class);

        foreach ($values as $key => $value) {
            $config->set($key, $value);
        }

        self::assertSame($mandatory, (new TenancySeams($container))->seams($config)[0]->isMandatory());
    }

    /**
     * MFA's tenant requirement bound off MFA's default makes the binding
     * mandatory, read only when the mandate is asked.
     *
     * @return void
     */
    public function testARequirementBoundMakesTheBindingMandatory(): void
    {
        $container = self::container();
        $binding   = (new TenancySeams($container))->seams(new Repository)[0];

        ScriptedTenantRequirement::bind($container);

        self::assertTrue($binding->isMandatory());
    }

    /**
     * With neither memberships nor a tree named or bound, SSO's defaults stay
     * for its tenant membership, link eligibility, principal scope and
     * enforcement inheritance, each of which refuses or stands each tenant
     * alone.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testWithoutMembershipsOrATreeSsosDefaultsStay(): void
    {
        self::assertInstanceOf(NoTenantMembership::class, $this->resolved(TenantMembership::class));
        self::assertInstanceOf(RefusingLinkEligibility::class, $this->resolved(LinkEligibility::class));
        self::assertInstanceOf(RefusingPrincipalScope::class, $this->resolved(PrincipalScope::class));
        self::assertInstanceOf(OwnTenantInheritance::class, $this->resolved(EnforcementInheritance::class));
    }

    /**
     * Memberships named bind the three adapters answered from them over SSO's
     * defaults, and leave the enforcement inheritance alone.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[WithConfig(TenancyContracts::MEMBERSHIPS, FakeMemberships::class, defer: false)]
    public function testMembershipsNamedBindTheMembershipAdapters(): void
    {
        self::assertInstanceOf(TenantMembershipAdapter::class, $this->resolved(TenantMembership::class));
        self::assertInstanceOf(LinkEligibilityAdapter::class, $this->resolved(LinkEligibility::class));
        self::assertInstanceOf(PrincipalScopeAdapter::class, $this->resolved(PrincipalScope::class));
        self::assertInstanceOf(OwnTenantInheritance::class, $this->resolved(EnforcementInheritance::class));
    }

    /**
     * A tree named binds the enforcement inheritance adapter over SSO's
     * default, and leaves the membership seams alone.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[WithConfig(TenancyContracts::TREE, FakeTenantTree::class, defer: false)]
    public function testATreeNamedBindsTheInheritanceAdapter(): void
    {
        self::assertInstanceOf(EnforcementInheritanceAdapter::class, $this->resolved(EnforcementInheritance::class));
        self::assertInstanceOf(NoTenantMembership::class, $this->resolved(TenantMembership::class));
    }

    /**
     * Memberships and a tree the application binds before any provider
     * registers bind the adapters in every provider order.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testMembershipsAndATreeBoundBeforeRegisteringBindTheAdaptersInEveryProviderOrder(array $providers): void
    {
        $this->bootInOrder($providers, before: [Memberships::class => new FakeMemberships, TenantTree::class => new FakeTenantTree]);

        self::assertInstanceOf(TenantMembershipAdapter::class, $this->resolved(TenantMembership::class));
        self::assertInstanceOf(LinkEligibilityAdapter::class, $this->resolved(LinkEligibility::class));
        self::assertInstanceOf(PrincipalScopeAdapter::class, $this->resolved(PrincipalScope::class));
        self::assertInstanceOf(EnforcementInheritanceAdapter::class, $this->resolved(EnforcementInheritance::class));
    }

    /**
     * Memberships and a tree bound once every provider has registered and
     * before any boots, where an application provider's `register()` binds,
     * bind the adapters over SSO's defaults, and the outcome kept for the
     * checks lists them as bound.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testMembershipsAndATreeBoundAfterRegisteringBindTheAdapters(): void
    {
        $this->bootInOrder([...self::MEMBER_PROVIDERS, IamServiceProvider::class], after: [Memberships::class => new FakeMemberships, TenantTree::class => new FakeTenantTree]);

        self::assertInstanceOf(TenantMembershipAdapter::class, $this->resolved(TenantMembership::class));
        self::assertInstanceOf(LinkEligibilityAdapter::class, $this->resolved(LinkEligibility::class));
        self::assertInstanceOf(PrincipalScopeAdapter::class, $this->resolved(PrincipalScope::class));
        self::assertInstanceOf(EnforcementInheritanceAdapter::class, $this->resolved(EnforcementInheritance::class));

        $outcome = $this->app?->make(BindingOutcome::class);

        self::assertInstanceOf(BindingOutcome::class, $outcome);
        self::assertSame([TenantMembership::class, LinkEligibility::class, PrincipalScope::class, EnforcementInheritance::class], array_slice($outcome->bound, -4));
    }

    /**
     * An application provider registered after every package provider, as
     * Laravel registers the application's own, that binds memberships and a
     * tree in its `register()` binds the adapters in every order of the
     * packages' providers, so SSO's enforcement inheritance and the revocations
     * answer from the same tree.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testAnApplicationProviderBindingTenancyWhileRegisteringBindsTheAdapters(array $providers): void
    {
        $this->bootInOrder([...$providers, BindsTenancyWhileRegistering::class]);

        self::assertInstanceOf(TenantMembershipAdapter::class, $this->resolved(TenantMembership::class));
        self::assertInstanceOf(LinkEligibilityAdapter::class, $this->resolved(LinkEligibility::class));
        self::assertInstanceOf(PrincipalScopeAdapter::class, $this->resolved(PrincipalScope::class));
        self::assertInstanceOf(EnforcementInheritanceAdapter::class, $this->resolved(EnforcementInheritance::class));
        self::assertSame($this->resolved(TenantTree::class), $this->app?->make(TenancyContracts::class)->tree());
    }

    /**
     * An application's own binding of SSO's seams, made where its tenancy is
     * bound, once every provider has registered, is kept, and the outcome kept
     * for the checks lists it as kept.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnApplicationsOwnBindingMadeAfterRegisteringIsKept(): void
    {
        $inheritance = \Mockery::mock(EnforcementInheritance::class);

        $after = [TenantTree::class => new FakeTenantTree, EnforcementInheritance::class => static fn (): object => $inheritance];

        $this->bootInOrder([...self::MEMBER_PROVIDERS, IamServiceProvider::class], after: $after);

        self::assertSame($inheritance, $this->resolved(EnforcementInheritance::class));

        $outcome = $this->app?->make(BindingOutcome::class);

        self::assertInstanceOf(BindingOutcome::class, $outcome);
        self::assertContains(EnforcementInheritance::class, $outcome->kept);
        self::assertNotContains(EnforcementInheritance::class, $outcome->bound);
    }

    /**
     * An application's own binding of SSO's seams to SSO's own default classes,
     * made in its provider's `register()` beside the memberships and the tree
     * it binds there, is kept in every provider order, though by its class it
     * reads as SSO's default: each tenant's SSO rule stays its own, and the
     * scope SSO's refusing default answers. The seams it leaves are bound, and
     * the outcome kept for the checks lists each as it was decided.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testAnApplicationsBindingOfSsosDefaultClassMadeWithItsTenancyIsKept(array $providers): void
    {
        $after = [
            TenantTree::class             => new FakeTenantTree,
            Memberships::class            => new FakeMemberships,
            EnforcementInheritance::class => OwnTenantInheritance::class,
            PrincipalScope::class         => RefusingPrincipalScope::class,
        ];

        $this->bootInOrder($providers, after: $after);

        self::assertInstanceOf(OwnTenantInheritance::class, $this->resolved(EnforcementInheritance::class));
        self::assertInstanceOf(RefusingPrincipalScope::class, $this->resolved(PrincipalScope::class));
        self::assertInstanceOf(TenantMembershipAdapter::class, $this->resolved(TenantMembership::class));
        self::assertInstanceOf(LinkEligibilityAdapter::class, $this->resolved(LinkEligibility::class));

        $outcome = $this->app?->make(BindingOutcome::class);

        self::assertInstanceOf(BindingOutcome::class, $outcome);
        self::assertSame([PrincipalScope::class, EnforcementInheritance::class], array_slice($outcome->kept, -2));
        self::assertSame([TenantMembership::class, LinkEligibility::class], array_slice($outcome->bound, -2));
    }

    /**
     * Memberships and a tree bound only from a provider's `boot()`, once the
     * booting callbacks have run, bind no adapter: SSO's defaults stay, as
     * documented, though the tree is still the one asked.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testMembershipsAndATreeBoundWhileBootingBindNothing(): void
    {
        $this->bootInOrder([...self::MEMBER_PROVIDERS, IamServiceProvider::class, BindsTenancyWhileBooting::class]);

        self::assertInstanceOf(NoTenantMembership::class, $this->resolved(TenantMembership::class));
        self::assertInstanceOf(OwnTenantInheritance::class, $this->resolved(EnforcementInheritance::class));
        self::assertInstanceOf(FakeTenantTree::class, $this->app?->make(TenancyContracts::class)->tree());
    }

    /**
     * With the SSO capability's switch off as the package registers, tenancy
     * bound once every provider has registered binds nothing over SSO's seams.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[WithConfig(SsoSeams::SWITCH, false, defer: false)]
    public function testWithTheSsoSwitchOffTenancyBoundLaterBindsNothing(): void
    {
        $this->bootInOrder([...self::MEMBER_PROVIDERS, IamServiceProvider::class, BindsTenancyWhileRegistering::class]);

        self::assertInstanceOf(NoTenantMembership::class, $this->resolved(TenantMembership::class));
        self::assertInstanceOf(OwnTenantInheritance::class, $this->resolved(EnforcementInheritance::class));
    }

    /**
     * The SSO capability's switch turned on by a provider registering after
     * this package comes too late for SSO's seams, and so for the tenancy bound
     * beside it: SSO's defaults stay.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[WithConfig(SsoSeams::SWITCH, false, defer: false)]
    public function testTheSsoSwitchTurnedOnAfterRegisteringBindsNoTenancy(): void
    {
        $this->bootInOrder([...self::MEMBER_PROVIDERS, IamServiceProvider::class, TurnsSsoOnWhileRegistering::class, BindsTenancyWhileRegistering::class]);

        self::assertTrue(SsoSeams::isOn($this->app?->make('config') ?? self::fail('The application has not booted.')));
        self::assertInstanceOf(NoTenantMembership::class, $this->resolved(TenantMembership::class));
        self::assertInstanceOf(OwnTenantInheritance::class, $this->resolved(EnforcementInheritance::class));
    }

    /**
     * The SSO capability's switch turned off by a provider registering after
     * this package comes too late for SSO's seams, and so for the tenancy bound
     * beside it: the rows applied again once every provider has registered
     * follow the switch as it read when this package registered, so SSO's
     * tenancy seams are bound with its other seams, not dropped from them.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheSsoSwitchTurnedOffAfterRegisteringStillBindsTheTenancy(): void
    {
        $this->bootInOrder([...self::MEMBER_PROVIDERS, IamServiceProvider::class, TurnsSsoOffWhileRegistering::class, BindsTenancyWhileRegistering::class]);

        self::assertFalse(SsoSeams::isOn($this->app?->make('config') ?? self::fail('The application has not booted.')));
        self::assertInstanceOf(SessionRevocationAdapter::class, $this->resolved(SessionRevocation::class));
        self::assertInstanceOf(TenantMembershipAdapter::class, $this->resolved(TenantMembership::class));
        self::assertInstanceOf(LinkEligibilityAdapter::class, $this->resolved(LinkEligibility::class));
        self::assertInstanceOf(PrincipalScopeAdapter::class, $this->resolved(PrincipalScope::class));
        self::assertInstanceOf(EnforcementInheritanceAdapter::class, $this->resolved(EnforcementInheritance::class));
    }

    /**
     * The rows follow the SSO capability's switch as it read when this package
     * registered, when given it, whatever the switches read by now; and the
     * switches themselves when not.
     *
     * @return void
     */
    public function testTheTenancyRowsFollowTheSwitchAsItReadWhenGivenIt(): void
    {
        $container = new Container;
        $off       = new Repository(['iam' => ['adapters' => ['sso' => false]]]);
        $on        = new Repository(['iam' => ['adapters' => ['sso' => true]]]);

        FakeMemberships::fake($container);
        FakeTenantTree::fake($container);

        foreach ([[true, $off, true], [false, $on, false], [null, $off, false], [null, $on, true]] as [$ssoOn, $switches, $applies]) {

            foreach (array_slice((new TenancySeams($container, $ssoOn))->seams($switches), 1) as $binding) {
                self::assertNotNull($binding->appliesWhen);
                self::assertSame($applies, ($binding->appliesWhen)($switches), $binding->abstract);
            }
        }
    }

    /**
     * The application's own bindings of the four seams are kept, memberships
     * and a tree named or not.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheApplicationsOwnBindingsAreKept(): void
    {
        $own = [
            TenantMembership::class       => \Mockery::mock(TenantMembership::class),
            LinkEligibility::class        => \Mockery::mock(LinkEligibility::class),
            PrincipalScope::class         => \Mockery::mock(PrincipalScope::class),
            EnforcementInheritance::class => \Mockery::mock(EnforcementInheritance::class),
        ];

        $tenancy = [Memberships::class => new FakeMemberships, TenantTree::class => new FakeTenantTree];

        $this->bootInOrder([...self::MEMBER_PROVIDERS, IamServiceProvider::class], before: [...$own, ...$tenancy]);

        foreach ($own as $abstract => $binding) {
            self::assertSame($binding, $this->resolved($abstract), $abstract);
        }
    }

    /**
     * Rows of `[sso switch, memberships named, memberships bound, tree named,
     * tree bound, memberships on, tree on]`.
     *
     * @return iterable<string, array{0: mixed, 1: mixed, 2: bool, 3: mixed, 4: bool, 5: bool, 6: bool}>
     */
    public static function provideTenancyRows(): iterable
    {
        yield 'nothing' => [true, null, false, null, false, false, false];

        yield 'memberships named' => [true, FakeMemberships::class, false, null, false, true, false];

        yield 'memberships blank' => [true, '  ', false, null, false, false, false];

        yield 'memberships misnamed' => [true, true, false, null, false, true, false];

        yield 'memberships bound' => [true, null, true, null, false, true, false];

        yield 'tree named' => [true, null, false, FakeTenantTree::class, false, false, true];

        yield 'tree bound' => [true, null, false, '', true, false, true];

        yield 'both, sso off' => ['off', FakeMemberships::class, true, FakeTenantTree::class, true, false, false];
    }

    /**
     * The membership rows are on while the SSO switch is and memberships are
     * named or bound; the inheritance row while the switch is and a tree is.
     *
     * @param  mixed  $sso
     * @param  mixed  $memberships
     * @param  bool  $membershipsBound
     * @param  mixed  $tree
     * @param  bool  $treeBound
     * @param  bool  $membershipsOn
     * @param  bool  $treeOn
     * @return void
     */
    #[DataProvider('provideTenancyRows')]
    public function testTheTenancyRowsFollowTheSwitchAndTheApplicationsTenancy(
        mixed $sso,
        mixed $memberships,
        bool $membershipsBound,
        mixed $tree,
        bool $treeBound,
        bool $membershipsOn,
        bool $treeOn,
    ): void {
        $container = new Container;
        $config    = new Repository(['iam' => ['adapters' => ['sso' => $sso], 'tenancy' => ['memberships' => $memberships, 'tree' => $tree]]]);

        if ($membershipsBound) {
            FakeMemberships::fake($container);
        }

        if ($treeBound) {
            FakeTenantTree::fake($container);
        }

        $bindings = (new TenancySeams($container))->seams($config);

        foreach (array_slice($bindings, 1, 3) as $binding) {
            self::assertNotNull($binding->appliesWhen);
            self::assertSame($membershipsOn, ($binding->appliesWhen)($config), $binding->abstract);
        }

        self::assertNotNull($bindings[4]->appliesWhen);
        self::assertSame($treeOn, ($bindings[4]->appliesWhen)($config));
    }

    /**
     * The tenancy rows replace SSO's own defaults, transient and never
     * mandatory.
     *
     * @return void
     */
    public function testTheTenancyRowsAreTransientOverSsosDefaults(): void
    {
        $rows = array_map(
            static fn (SeamBinding $binding): array => [$binding->abstract, $binding->adapter, $binding->memberDefaults, $binding->lifetime, $binding->mandatory],
            array_slice((new TenancySeams(new Container))->seams(new Repository), 1),
        );

        self::assertSame([
            [TenantMembership::class, TenantMembershipAdapter::class, [NoTenantMembership::class], Lifetime::TRANSIENT, false],
            [LinkEligibility::class, LinkEligibilityAdapter::class, [RefusingLinkEligibility::class], Lifetime::TRANSIENT, false],
            [PrincipalScope::class, PrincipalScopeAdapter::class, [RefusingPrincipalScope::class], Lifetime::TRANSIENT, false],
            [EnforcementInheritance::class, EnforcementInheritanceAdapter::class, [OwnTenantInheritance::class], Lifetime::TRANSIENT, false],
        ], $rows);
    }

    /**
     * The grant half of SSO's principal scope is `laravel-authorization`'s
     * grant scope query (`GrantScopeAdapter`), transient, until something else
     * is bound to it, before or after the providers register, which is kept.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheGrantScopeIsAuthorizationsQueryUntilTheApplicationBindsOne(): void
    {
        $default = $this->resolved(GrantScope::class);

        self::assertInstanceOf(GrantScopeAdapter::class, $default);
        self::assertNotSame($default, $this->resolved(GrantScope::class));

        $before = \Mockery::mock(GrantScope::class);
        $after  = \Mockery::mock(GrantScope::class);

        $this->bootInOrder([...self::MEMBER_PROVIDERS, IamServiceProvider::class], before: [GrantScope::class => $before]);

        self::assertSame($before, $this->resolved(GrantScope::class));

        $this->bootInOrder([...self::MEMBER_PROVIDERS, IamServiceProvider::class], after: [GrantScope::class => $after]);

        self::assertSame($after, $this->resolved(GrantScope::class));
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
     * Assert the binding rule bound the seam, or kept the application's.
     *
     * @param  bool  $bound
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function assertOutcome(bool $bound): void
    {
        $outcome = $this->app?->make(BindingOutcome::class);

        self::assertInstanceOf(BindingOutcome::class, $outcome);
        self::assertSame($bound, in_array(TenantAuthenticationPolicy::class, $outcome->bound, true));
        self::assertSame(!$bound, in_array(TenantAuthenticationPolicy::class, $outcome->kept, true));
    }

    /**
     * A container that resolves its own contract, as the application's does.
     *
     * @return \Illuminate\Container\Container
     */
    private static function container(): Container
    {
        $container = new Container;

        $container->instance(ContainerContract::class, $container);

        return $container;
    }
}
