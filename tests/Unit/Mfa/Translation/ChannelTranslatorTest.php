<?php

declare(strict_types = 1);

namespace Tests\Unit\Mfa\Translation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Proofs\Channel as AuthenticationChannel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind as AuthenticationChannelKind;
use SineMacula\Laravel\Iam\Mfa\Translation\ChannelTranslator;
use SineMacula\Laravel\Mfa\Assurance\Channel as MfaChannel;
use SineMacula\Laravel\Mfa\Enums\ChannelKind as MfaChannelKind;

/**
 * Unit tests for translating a proof's channel both ways.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ChannelTranslator::class)]
final class ChannelTranslatorTest extends TestCase
{
    /** @var string The reference the channels name, where their kind takes one. */
    private const string REFERENCE = 'ada@example.test';

    /**
     * Rows of `[authentication kind, MFA kind, whether the reference crosses]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind, 1: \SineMacula\Laravel\Mfa\Enums\ChannelKind, 2: bool}>
     */
    public static function provideChannelKinds(): iterable
    {
        yield 'password' => [AuthenticationChannelKind::PASSWORD, MfaChannelKind::PASSWORD, false];

        yield 'sms' => [AuthenticationChannelKind::SMS, MfaChannelKind::SMS, true];

        yield 'email' => [AuthenticationChannelKind::EMAIL, MfaChannelKind::EMAIL, true];

        yield 'authenticator app' => [AuthenticationChannelKind::AUTHENTICATOR_APP, MfaChannelKind::AUTHENTICATOR_APP, true];

        yield 'passkey' => [AuthenticationChannelKind::PASSKEY, MfaChannelKind::PASSKEY, true];

        yield 'external provider' => [AuthenticationChannelKind::EXTERNAL_PROVIDER, MfaChannelKind::EXTERNAL_PROVIDER, true];

        yield 'unknown' => [AuthenticationChannelKind::UNKNOWN, MfaChannelKind::UNKNOWN, false];
    }

    /**
     * Every channel kind crosses to MFA's, with a reference where it takes one.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind  $authentication
     * @param  \SineMacula\Laravel\Mfa\Enums\ChannelKind  $mfa
     * @param  bool  $crosses
     * @return void
     */
    #[DataProvider('provideChannelKinds')]
    public function testEveryKindIsMfasOfTheSameKind(AuthenticationChannelKind $authentication, MfaChannelKind $mfa, bool $crosses): void
    {
        $translated = (new ChannelTranslator)->toMfa(new AuthenticationChannel($authentication, self::REFERENCE));

        self::assertSame($mfa, $translated->kind);
        self::assertSame($crosses ? self::REFERENCE : null, $translated->reference());
        self::assertNull((new ChannelTranslator)->toMfa(new AuthenticationChannel($authentication))->reference());
    }

    /**
     * The application's `recovery` channel is MFA's `unknown`.
     *
     * @return void
     */
    public function testARecoveryChannelIsMfasUnknown(): void
    {
        $translator = new ChannelTranslator;
        $translated = $translator->toMfa(new AuthenticationChannel(AuthenticationChannelKind::RECOVERY, self::REFERENCE));

        self::assertSame(MfaChannelKind::UNKNOWN, $translated->kind);
        self::assertNull($translated->reference());
        self::assertSame(['kind' => 'unknown', 'reference' => null], $translator->toArray(new AuthenticationChannel(AuthenticationChannelKind::RECOVERY)));
    }

    /**
     * Every MFA channel kind crosses back as the same kind.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind  $authentication
     * @param  \SineMacula\Laravel\Mfa\Enums\ChannelKind  $mfa
     * @param  bool  $crosses
     * @return void
     */
    #[DataProvider('provideChannelKinds')]
    public function testEveryKindIsLaravelAuthenticationsOfTheSameKind(AuthenticationChannelKind $authentication, MfaChannelKind $mfa, bool $crosses): void
    {
        $translated = (new ChannelTranslator)->toAuthentication(new MfaChannel($mfa, $crosses ? self::REFERENCE : null));

        self::assertSame($authentication, $translated->kind);
        self::assertSame($crosses ? self::REFERENCE : null, $translated->reference);
    }

    /**
     * The array form is MFA's and reads back as the same channel.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind  $authentication
     * @param  \SineMacula\Laravel\Mfa\Enums\ChannelKind  $mfa
     * @param  bool  $crosses
     * @return void
     */
    #[DataProvider('provideChannelKinds')]
    public function testTheArrayFormIsMfasAndReadsBack(AuthenticationChannelKind $authentication, MfaChannelKind $mfa, bool $crosses): void
    {
        $translator = new ChannelTranslator;
        $reference  = $crosses ? self::REFERENCE : null;
        $array      = $translator->toArray(new AuthenticationChannel($authentication, self::REFERENCE));

        self::assertSame(['kind' => $mfa->value, 'reference' => $reference], $array);

        $read = $translator->fromArray($array);

        self::assertSame($authentication, $read->kind);
        self::assertSame($reference, $read->reference);
    }

    /**
     * An array form MFA would refuse is refused.
     *
     * @return void
     */
    public function testAnArrayFormMfaWouldRefuseIsRefused(): void
    {
        $refused = [
            ['kind' => 'sms', 'reference' => self::REFERENCE, 'destination' => self::REFERENCE],
            ['kind' => 'pigeon', 'reference' => null],
            ['kind' => 'password', 'reference' => 'a password names nothing'],
        ];

        $refusals = 0;

        foreach ($refused as $array) {

            try {
                (new ChannelTranslator)->fromArray($array);
            } catch (\InvalidArgumentException) {
                $refusals++;
            }
        }

        self::assertSame(count($refused), $refusals);
    }
}
