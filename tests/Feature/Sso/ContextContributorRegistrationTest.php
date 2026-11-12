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
use SineMacula\Laravel\Iam\Mfa\MfaContextContributor;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use SineMacula\Laravel\Iam\Mfa\ProofStoreAdapter;
use SineMacula\Laravel\Iam\Sso\ExternalEvidencePolicyAdapter;
use SineMacula\Laravel\Iam\Sso\SsoContextContributor;
use SineMacula\Laravel\Iam\Sso\SsoSeams;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use Tests\Concerns\PermutesProviderOrder;
use Tests\Fixtures\Providers\RegistersAnMfaContributor;
use Tests\Fixtures\Providers\RegistersAnSsoContributor;
use Tests\Fixtures\Providers\RegistersAuthenticationWhileBooting;
use Tests\Fixtures\Providers\TurnsMfaOffWhileRegistering;
use Tests\Fixtures\Providers\TurnsSsoOffWhileRegistering;
use Tests\Fixtures\Providers\TurnsSsoOnWhileRegistering;
use Tests\TestCase;

/**
 * Feature tests for the `mfa` and `sso` namespaces' registration with
 * `laravel-authentication`'s authentication context: this package registers its
 * contributor under each exactly once, once every provider has booted, in every
 * provider order, `laravel-authentication` registered from another provider's
 * `boot()` included, and only while the matching capability's switch is on as
 * the seams were bound, so the contributor and the adapters agree; a
 * contributor the application registered under either namespace from any
 * provider's `boot()` is kept, and one it registers once the application has
 * booted is `laravel-authentication`'s refusal.
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

    /** @var array<string, string> This package's contributors, by namespace. */
    private const array CONTRIBUTORS = ['mfa' => MfaContextContributor::class, 'sso' => SsoContextContributor::class];

    /**
     * The contributors are registered under `mfa` and `sso`, once each, in
     * every provider order.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testTheContributorsAreRegisteredInEveryProviderOrder(array $providers): void
    {
        $this->bootInOrder($providers);

        self::assertSame(self::CONTRIBUTORS, $this->registered());
    }

    /**
     * With the SSO capability's switch off, nothing is registered under `sso`,
     * and the `mfa` contributor still is.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[WithConfig(SsoSeams::SWITCH, false, defer: false)]
    public function testTheSwitchOffRegistersNothing(): void
    {
        self::assertSame(['mfa' => MfaContextContributor::class], $this->registered());
    }

    /**
     * With the MFA capability's switch off, nothing is registered under `mfa`,
     * and the `sso` contributor still is.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[WithConfig(MfaSeams::SWITCH, false, defer: false)]
    public function testTheMfaSwitchOffRegistersNothingUnderMfa(): void
    {
        self::assertSame(['sso' => SsoContextContributor::class], $this->registered());
    }

    /**
     * The MFA switch turned off in a later provider's `register()` turns off
     * the bindings and the contributor alike.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheMfaSwitchTurnedOffWhileRegisteringTurnsOffTheBindingsAndTheContributor(): void
    {
        $this->bootInOrder([...self::MEMBER_PROVIDERS, IamServiceProvider::class, TurnsMfaOffWhileRegistering::class]);

        self::assertFalse(MfaSeams::isOn($this->application()->make('config')));
        self::assertNotInstanceOf(ProofStoreAdapter::class, $this->bound(ProofStore::class));
        self::assertSame(['sso' => SsoContextContributor::class], $this->registered());
    }

    /**
     * A contributor the application registered under `mfa` before this package
     * booted is kept.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnApplicationsEarlierMfaContributorIsKept(): void
    {
        $this->bootInOrder([...self::MEMBER_PROVIDERS, RegistersAnMfaContributor::class, IamServiceProvider::class]);

        self::assertSame(['mfa' => RegistersAnMfaContributor::CONTRIBUTOR, 'sso' => SsoContextContributor::class], $this->registered());
    }

    /**
     * A contributor the application registers under `mfa` from a provider that
     * boots after this package is kept too.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnApplicationsLaterMfaContributorIsKept(): void
    {
        $this->bootInOrder([...self::MEMBER_PROVIDERS, IamServiceProvider::class, RegistersAnMfaContributor::class]);

        self::assertSame(['mfa' => RegistersAnMfaContributor::CONTRIBUTOR, 'sso' => SsoContextContributor::class], $this->registered());
    }

    /**
     * The SSO switch turned off in a later provider's `register()` turns off
     * the bindings and the contributor alike.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheSwitchTurnedOffWhileRegisteringTurnsOffTheBindingsAndTheContributor(): void
    {
        $this->bootInOrder([...self::MEMBER_PROVIDERS, IamServiceProvider::class, TurnsSsoOffWhileRegistering::class]);

        self::assertFalse(SsoSeams::isOn($this->application()->make('config')));
        self::assertInstanceOf(InsufficientExternalEvidence::class, $this->bound(ExternalEvidencePolicy::class));
        self::assertSame(['mfa' => MfaContextContributor::class], $this->registered());
    }

    /**
     * The SSO switch turned on in a later provider's `register()` turns on the
     * bindings and the contributor alike.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheSwitchTurnedOnWhileRegisteringTurnsOnTheBindingsAndTheContributor(): void
    {
        $this->bootInOrder([TurnsSsoOffWhileRegistering::class, ...self::MEMBER_PROVIDERS, IamServiceProvider::class, TurnsSsoOnWhileRegistering::class]);

        self::assertTrue(SsoSeams::isOn($this->application()->make('config')));
        self::assertInstanceOf(ExternalEvidencePolicyAdapter::class, $this->bound(ExternalEvidencePolicy::class));
        self::assertSame(self::CONTRIBUTORS, $this->registered());
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

        self::assertSame(['mfa' => MfaContextContributor::class, 'sso' => RegistersAnSsoContributor::CONTRIBUTOR], $this->registered());
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

        self::assertSame(['mfa' => MfaContextContributor::class, 'sso' => RegistersAnSsoContributor::CONTRIBUTOR], $this->registered());
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

        self::assertSame(self::CONTRIBUTORS, $this->registered());
    }

    /**
     * The contributors `laravel-authentication` holds, by namespace, in the
     * namespaces' order rather than the order they were registered in.
     *
     * @return array<string, string>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function registered(): array
    {
        $registered = $this->application()->make(ContextContributors::class)->registered();

        ksort($registered);

        return $registered;
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
