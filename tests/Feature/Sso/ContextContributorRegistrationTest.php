<?php

declare(strict_types = 1);

namespace Tests\Feature\Sso;

use Illuminate\Contracts\Foundation\Application;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authentication\Context\ContextContributors;
use SineMacula\Laravel\Authentication\Contracts\ExternalEvidencePolicy;
use SineMacula\Laravel\Authentication\External\InsufficientEvidence as InsufficientExternalEvidence;
use SineMacula\Laravel\Iam\IamServiceProvider;
use SineMacula\Laravel\Iam\Sso\ExternalEvidencePolicyAdapter;
use SineMacula\Laravel\Iam\Sso\SsoContextContributor;
use SineMacula\Laravel\Iam\Sso\SsoSeams;
use Tests\Concerns\PermutesProviderOrder;
use Tests\Fixtures\Providers\RegistersAnSsoContributor;
use Tests\Fixtures\Providers\RegistersAuthenticationWhileBooting;
use Tests\Fixtures\Providers\TurnsSsoOffWhileRegistering;
use Tests\Fixtures\Providers\TurnsSsoOnWhileRegistering;
use Tests\TestCase;

/**
 * Feature tests for the `sso` namespace's registration with
 * `laravel-authentication`'s authentication context: this package registers its
 * contributor under `sso` exactly once, once every provider has booted, in
 * every provider order, `laravel-authentication` registered from another
 * provider's `boot()` included, and only while the SSO capability's switch is
 * on as the binding rule read it, so a provider that turns the switch over
 * once this package has registered leaves the contributor and the adapters
 * agreeing; a contributor the application registered under `sso` from any provider's
 * `boot()` is kept, and one it registers once the application has booted is
 * `laravel-authentication`'s refusal.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IamServiceProvider::class)]
final class ContextContributorRegistrationTest extends TestCase
{
    use PermutesProviderOrder;

    /**
     * The contributor is registered under `sso`, once, in every provider order.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testTheContributorIsRegisteredUnderSsoInEveryProviderOrder(array $providers): void
    {
        $this->bootInOrder($providers);

        self::assertSame(['sso' => SsoContextContributor::class], $this->registered());
    }

    /**
     * With the capability's switch off, nothing is registered under `sso`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[WithConfig(SsoSeams::SWITCH, false, defer: false)]
    public function testTheSwitchOffRegistersNothing(): void
    {
        self::assertSame([], $this->registered());
    }

    /**
     * A provider that turns the switch off once this package has registered, as
     * an application provider's `register()` does, comes too late for the
     * bindings and for the contributor alike: both stay on.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheSwitchTurnedOffLaterLeavesTheBindingsAndTheContributorOn(): void
    {
        $this->bootInOrder([...self::MEMBER_PROVIDERS, IamServiceProvider::class, TurnsSsoOffWhileRegistering::class]);

        self::assertFalse(SsoSeams::isOn($this->application()->make('config')));
        self::assertInstanceOf(ExternalEvidencePolicyAdapter::class, $this->bound(ExternalEvidencePolicy::class));
        self::assertSame(['sso' => SsoContextContributor::class], $this->registered());
    }

    /**
     * A provider that turns the switch on once this package has registered with
     * it off comes too late for the bindings and for the contributor alike:
     * both stay off.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheSwitchTurnedOnLaterLeavesTheBindingsAndTheContributorOff(): void
    {
        $this->bootInOrder([TurnsSsoOffWhileRegistering::class, ...self::MEMBER_PROVIDERS, IamServiceProvider::class, TurnsSsoOnWhileRegistering::class]);

        self::assertTrue(SsoSeams::isOn($this->application()->make('config')));
        self::assertInstanceOf(InsufficientExternalEvidence::class, $this->bound(ExternalEvidencePolicy::class));
        self::assertSame([], $this->registered());
    }

    /**
     * A contributor the application registered under `sso` before this package
     * booted is kept.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnApplicationsEarlierContributorIsKept(): void
    {
        $this->bootInOrder([...self::MEMBER_PROVIDERS, RegistersAnSsoContributor::class, IamServiceProvider::class]);

        self::assertSame(['sso' => RegistersAnSsoContributor::CONTRIBUTOR], $this->registered());
    }

    /**
     * A contributor the application registers under `sso` from a provider that
     * boots after this package is kept too: this package registers its own only
     * once every provider has booted.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnApplicationsContributorRegisteredAfterThisPackageBootedIsKept(): void
    {
        $this->bootInOrder([...self::MEMBER_PROVIDERS, IamServiceProvider::class, RegistersAnSsoContributor::class]);

        self::assertSame(['sso' => RegistersAnSsoContributor::CONTRIBUTOR], $this->registered());
    }

    /**
     * A contributor the application registers under `sso` once the application
     * has booted is `laravel-authentication`'s `LogicException`: a namespace is
     * taken once.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnApplicationsContributorRegisteredOnceBootedIsRefused(): void
    {
        $contributors = ($this->app ?? self::fail('The application has not booted.'))->make(ContextContributors::class);

        $this->expectException(\LogicException::class);

        $contributors->register('sso', RegistersAnSsoContributor::CONTRIBUTOR);
    }

    /**
     * With `laravel-authentication` registered from another provider's
     * `boot()`, after this package's has run, the contributor is still
     * registered, with the authentication context's contributors that member
     * binds then, never with an instance nobody keeps.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheContributorIsRegisteredWhenAuthenticationRegistersWhileBooting(): void
    {
        $members = array_values(array_filter(self::MEMBER_PROVIDERS, static fn (string $provider): bool => $provider !== AuthenticationServiceProvider::class));

        $this->bootInOrder([IamServiceProvider::class, ...$members, RegistersAuthenticationWhileBooting::class]);

        self::assertSame(['sso' => SsoContextContributor::class], $this->registered());
    }

    /**
     * The contributors `laravel-authentication` holds, by namespace.
     *
     * @return array<string, string>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function registered(): array
    {
        return $this->application()->make(ContextContributors::class)->registered();
    }

    /**
     * What the application resolves the seam to.
     *
     * @param  class-string  $seam
     * @return object
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function bound(string $seam): object
    {
        return $this->application()->make($seam);
    }

    /**
     * The application booted for the test.
     *
     * @return \Illuminate\Contracts\Foundation\Application
     */
    private function application(): Application
    {
        return $this->app ?? self::fail('The application has not booted.');
    }
}
