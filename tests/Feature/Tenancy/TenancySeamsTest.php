<?php

declare(strict_types = 1);

namespace Tests\Feature\Tenancy;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Tenancy\RequireNothingOfTenants;
use SineMacula\Laravel\Iam\Bindings\BindingOutcome;
use SineMacula\Laravel\Iam\Bindings\Enums\Lifetime;
use SineMacula\Laravel\Iam\Contracts\TenantMfaRequirement;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use SineMacula\Laravel\Iam\Sso\SsoSeams;
use SineMacula\Laravel\Iam\Tenancy\TenancySeams;
use SineMacula\Laravel\Iam\Tenancy\TenantAuthenticationPolicyAdapter;
use SineMacula\Laravel\Iam\Tenancy\TenantMfaRequirements;
use SineMacula\Laravel\Iam\Testing\FakeTenantMfaRequirement;
use Tests\Concerns\PermutesProviderOrder;
use Tests\TestCase;

/**
 * Feature tests for the seam the tenants' authentication policy is answered
 * through (IAM-4.5): the composite adapter replaces `laravel-authentication`'s
 * default in every provider order; an application's own binding is kept or wins
 * as the binding rule says (IAM-8.4); it is bound while the SSO capability's
 * switch is on, whatever MFA's, and not while it is off, MFA's on or not; and
 * it is mandatory while SSO's enforcement is on or the application names or
 * binds a tenant MFA requirement.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TenancySeams::class)]
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
     * `laravel-authentication`'s default stays, a tenant MFA requirement named
     * or not: the adapter would find no sign-in's connection, which only the
     * SSO capability records, so the policy is the application's to bind.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[WithConfig(MfaSeams::SWITCH, true, defer: false)]
    #[WithConfig(SsoSeams::SWITCH, false, defer: false)]
    #[WithConfig(TenantMfaRequirements::KEY, FakeTenantMfaRequirement::class, defer: false)]
    public function testMfaOnWithSsoOffBindsNothing(): void
    {
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

        self::assertCount(1, $bindings);
        self::assertSame(TenantAuthenticationPolicy::class, $bindings[0]->abstract);
        self::assertSame(TenantAuthenticationPolicyAdapter::class, $bindings[0]->adapter);
        self::assertSame([RequireNothingOfTenants::class], $bindings[0]->memberDefaults);
        self::assertSame(Lifetime::TRANSIENT, $bindings[0]->lifetime);
    }

    /**
     * Rows of `[configuration, mandatory]`: SSO's enforcement and the
     * application's tenant MFA requirement as configured, and whether the
     * binding is mandatory.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: bool}>
     */
    public static function provideMandates(): iterable
    {
        yield 'neither' => [[], false];

        yield 'enforcement off' => [[TenancySeams::ENFORCEMENT => false], false];

        yield 'enforcement on' => [[TenancySeams::ENFORCEMENT => true], true];

        yield 'enforcement on, as an environment variable fills it' => [[TenancySeams::ENFORCEMENT => 'true'], true];

        yield 'a requirement named' => [[TenantMfaRequirements::KEY => FakeTenantMfaRequirement::class], true];

        yield 'a blank requirement' => [[TenantMfaRequirements::KEY => ' '], false];
    }

    /**
     * The binding is mandatory while SSO's enforcement is on or the application
     * names a tenant MFA requirement.
     *
     * @param  array<string, mixed>  $values
     * @param  bool  $mandatory
     * @return void
     */
    #[DataProvider('provideMandates')]
    public function testTheBindingIsMandatoryWhileEnforcementOrARequirementIsOn(array $values, bool $mandatory): void
    {
        $config = new Repository;

        foreach ($values as $key => $value) {
            $config->set($key, $value);
        }

        self::assertSame($mandatory, (new TenancySeams(new Container))->seams($config)[0]->mandatory);
    }

    /**
     * A tenant MFA requirement the application binds makes the binding
     * mandatory, as one it names does.
     *
     * @return void
     */
    public function testARequirementBoundMakesTheBindingMandatory(): void
    {
        $container = new Container;

        FakeTenantMfaRequirement::fake($container);

        self::assertTrue($container->bound(TenantMfaRequirement::class));
        self::assertTrue((new TenancySeams($container))->seams(new Repository)[0]->mandatory);
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
}
