<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyRegistration;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyService;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding;
use Tests\Fixtures\Passkeys\VirtualAuthenticator;

/**
 * Registers passkeys through `laravel-authentication`'s public passkey service,
 * as a browser would, with a virtual authenticator that signs with real keys,
 * so a registration runs the passkey factor gate inside
 * `laravel-authentication`'s passkey transaction exactly as a real one does.
 *
 * Using it offers `passkey` as a factor type of the MFA application people sign
 * in on, and allows the `passkey` sign-in method on its guard, both before any
 * provider registers, so the binding rule binds the passkey adapters
 * (IAM-3.10). The relying party is the one the base test case configures. The
 * tables come from `MigratesMembers`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \Tests\TestCase
 */
trait RegistersPasskeys
{
    /** @var ?\Tests\Fixtures\Passkeys\VirtualAuthenticator The authenticator the test registers and signs with. */
    private ?VirtualAuthenticator $virtualAuthenticator = null;

    /**
     * The virtual authenticator the test registers and signs with, created on
     * first use on the origin the relying party allows.
     *
     * @return \Tests\Fixtures\Passkeys\VirtualAuthenticator
     */
    protected function authenticator(): VirtualAuthenticator
    {
        return $this->virtualAuthenticator ??= new VirtualAuthenticator(self::ORIGIN);
    }

    /**
     * Register a passkey for the identity through the guard's passkey service,
     * under the credential id given (unpadded base64url) or a random one, with
     * the registration challenge bound as given (an MFA enrolment's binding, so
     * MFA associates it as a factor), and return the registration.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?string  $credentialId
     * @param  ?\SineMacula\Laravel\Authentication\Proofs\ProofBinding  $binding
     * @param  string  $guard
     * @param  ?string  $name
     * @return \SineMacula\Laravel\Authentication\Passkeys\PasskeyRegistration
     *
     * @throws \Throwable
     */
    protected function registerPasskey(
        Identity $identity,
        #[\SensitiveParameter] ?string $credentialId = null,
        ?ProofBinding $binding = null,
        string $guard = self::GUARD,
        ?string $name = 'Laptop',
    ): PasskeyRegistration {
        $passkeys = $this->passkeys($guard);
        $options  = $passkeys->registrationOptions($identity, 'person@example.test', binding: $binding);
        $id       = $credentialId === null ? null : VirtualAuthenticator::decode($credentialId);

        return $passkeys->register($identity, $options->challengeId, $this->authenticator()->create($options->options, id: $id), self::client(), $name);
    }

    /**
     * `laravel-authentication`'s passkey service for the guard.
     *
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Passkeys\PasskeyService
     */
    protected function passkeys(string $guard = self::GUARD): PasskeyService
    {
        $auth = $this->app?->make('auth');

        self::assertInstanceOf(AuthManager::class, $auth);

        return $auth->passkeys($guard);
    }

    /**
     * Offer `passkey` as a factor type of the MFA application, beside TOTP.
     *
     * @return list<string>
     */
    #[\Override]
    protected function mfaTypes(): array
    {
        return ['totp', 'passkey'];
    }

    /**
     * Allow the `passkey` sign-in method on the guard, beside the password.
     *
     * @return list<string>
     */
    #[\Override]
    protected function signInMethods(): array
    {
        return ['password', 'passkey'];
    }
}
