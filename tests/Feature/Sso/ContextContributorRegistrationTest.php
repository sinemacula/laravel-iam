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
 * Feature tests for registering the `mfa` and `sso` context contributors.
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
     * The SSO switch off registers nothing under `sso`.
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
     * The MFA switch off registers nothing under `mfa`.
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
     * The MFA switch turned off in a later `register()` turns off the bindings
     * and the contributor alike.
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
     * An application's earlier `mfa` contributor is kept.
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
     * An application's `mfa` contributor from a later-booting provider is kept.
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
     * The SSO switch turned off in a later `register()` turns off the bindings
     * and the contributor alike.
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
     * The SSO switch turned on in a later `register()` turns on the bindings
     * and the contributor alike.
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
     * An application's earlier `sso` contributor is kept.
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
     * An application's `sso` contributor from a later-booting provider is kept.
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
     * An `sso` contributor registered once booted is `laravel-authentication`'s
     * `LogicException`.
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
     * The contributor is registered when `laravel-authentication` registers
     * from another provider's `boot()`.
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
     * namespaces' order.
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
