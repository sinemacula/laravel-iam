<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use PHPUnit\Framework\Attributes\CoversNothing;
use SineMacula\Laravel\Authentication\Contracts\PasskeyFactorGate;
use SineMacula\Laravel\Authentication\Models\Passkey;
use SineMacula\Laravel\Authentication\Passkeys\NoPasskeyFactors;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\RegistersPasskeys;
use Tests\Concerns\SignsInPeople;
use Tests\TestCase;

/**
 * Integration tests for the passkey fixtures the adapters of passkeys as
 * factors start from (IAM-3.10): the MFA application offers passkeys, and a
 * passkey registers through `laravel-authentication`'s public passkey service
 * with the virtual authenticator, under a random credential id or the one the
 * test names.
 *
 * MFA refuses to boot while it offers passkeys with no passkey gateway of its
 * own, so this package's adapters stay bound; the passkey factor gate is bound
 * back to `laravel-authentication`'s default, as the application's binding, so
 * the fixtures are shown working apart from this package's gate.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class RegistersPasskeysTest extends TestCase
{
    use MigratesMembers, RegistersPasskeys, SignsInPeople;

    /** @var string A credential id, in unpadded base64url, as MFA's passkey change gate kit names one. */
    private const string CREDENTIAL = 'Y29udHJhY3QtY3JlZGVudGlhbA';

    /**
     * The MFA application offers passkeys beside TOTP, and the guard allows
     * signing in with one.
     *
     * @return void
     */
    public function testTheApplicationOffersPasskeys(): void
    {
        self::assertSame(['totp', 'passkey'], config('mfa.applications.' . self::GUARD . '.types'));
        self::assertSame(['password', 'passkey'], config('auth.guards.' . self::GUARD . '.application.methods'));
    }

    /**
     * A passkey registers under the credential id the test names.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPasskeyRegistersUnderTheCredentialIdNamed(): void
    {
        $person       = $this->createPerson();
        $registration = $this->registerPasskey($person, self::CREDENTIAL);

        self::assertTrue($registration->isRegistered());
        self::assertNull($registration->factor);
        self::assertSame([self::CREDENTIAL], Passkey::query()->pluck('credential_id')->all());
    }

    /**
     * Passkeys registered without a credential id named each get a random one
     * of their own.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPasskeysRegisterUnderRandomCredentialIds(): void
    {
        $person = $this->createPerson();

        self::assertTrue($this->registerPasskey($person)->isRegistered());
        self::assertTrue($this->registerPasskey($person)->isRegistered());
        self::assertSame(2, Passkey::query()->distinct()->count('credential_id'));
        self::assertCount(2, $this->passkeys()->passkeys($person));
    }

    /**
     * Seed the environment, then bind `laravel-authentication`'s own passkey
     * factor gate as the application's, once every provider has registered.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $app->singleton(PasskeyFactorGate::class, NoPasskeyFactors::class);
    }
}
