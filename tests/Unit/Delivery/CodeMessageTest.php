<?php

declare(strict_types = 1);

namespace Tests\Unit\Delivery;

use Carbon\CarbonImmutable;
use Illuminate\Auth\GenericUser;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodeMessage;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Exceptions\SecretNotRevealedException;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Iam\Delivery\CodeMessage;
use SineMacula\Laravel\Iam\Delivery\Enums\Channel;
use SineMacula\Laravel\Iam\Delivery\Enums\Purpose;
use SineMacula\Laravel\Iam\Delivery\Enums\Source;
use SineMacula\Laravel\Mfa\Codes\CodeMessage as MfaCodeMessage;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Enums\Purpose as MfaPurpose;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;

/**
 * Unit tests for the one code message both members' codes reach the
 * application's gateways as (IAM-3.13): it carries the same neutral details
 * whichever member issued the code, says what the code is for in this package's
 * own words and the member's, and gives up neither the code, the destination
 * nor the recipient to a dump, a serialiser or a JSON encoder.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CodeMessage::class)]
final class CodeMessageTest extends TestCase
{
    /** @var string The code every message carries. */
    private const string CODE = '493027';

    /** @var string The address every email message goes to. */
    private const string ADDRESS = 'ada@example.test';

    /** @var string The number every SMS message goes to. */
    private const string NUMBER = '+447700900123';

    /** @var string The application every message is for. */
    private const string APPLICATION = 'api';

    /**
     * Close Mockery's container, so each expectation is checked.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        \Mockery::close();

        parent::tearDown();
    }

    /**
     * A message carries the details it was given, reads its destination and
     * recipient back, and says what the code is for and which member it came
     * from.
     *
     * @return void
     */
    public function testAMessageCarriesTheDetailsGiven(): void
    {
        $recipient = new GenericUser(['id' => 7]);
        $code      = new Secret(self::CODE);
        $expiresAt = CarbonImmutable::parse('2026-11-05 12:10:00');
        $factor    = self::factor();

        $message = new CodeMessage(self::APPLICATION, MfaPurpose::STEP_UP, Channel::SMS, 'sms', self::NUMBER, $code, $expiresAt, $recipient, $factor);

        self::assertSame(self::APPLICATION, $message->application);
        self::assertSame(MfaPurpose::STEP_UP, $message->memberPurpose);
        self::assertSame(Purpose::ADDITIONAL_FACTOR, $message->purpose);
        self::assertSame(Source::MFA, $message->source);
        self::assertSame(Channel::SMS, $message->channel);
        self::assertSame('sms', $message->type);
        self::assertSame(self::NUMBER, $message->destination());
        self::assertSame($code, $message->code);
        self::assertSame($expiresAt, $message->expiresAt);
        self::assertSame($recipient, $message->recipient());
        self::assertSame($factor, $message->factor);
    }

    /**
     * A message names no factor unless one is given.
     *
     * @return void
     */
    public function testAMessageNamesNoFactorUnlessOneIsGiven(): void
    {
        self::assertNull(self::message()->factor);
    }

    /**
     * Rows of `[laravel-authentication's purpose, this package's purpose]` for
     * a code of each kind.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose, 1: \SineMacula\Laravel\Iam\Delivery\Enums\Purpose}>
     */
    public static function provideAuthenticationPurposes(): iterable
    {
        yield 'sign-in' => [CodePurpose::SIGN_IN, Purpose::SIGN_IN];

        yield 'mfa' => [CodePurpose::MFA, Purpose::ADDITIONAL_FACTOR];

        yield 'identifier change' => [CodePurpose::CHANGE_IDENTIFIER, Purpose::IDENTIFIER_CHANGE];
    }

    /**
     * A message for a code of `laravel-authentication`'s says so, and its
     * purpose follows `laravel-authentication`'s.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose  $memberPurpose
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Purpose  $purpose
     * @return void
     */
    #[DataProvider('provideAuthenticationPurposes')]
    public function testThePurposeFollowsAnAuthenticationPurpose(CodePurpose $memberPurpose, Purpose $purpose): void
    {
        $message = self::message($memberPurpose);

        self::assertSame($memberPurpose, $message->memberPurpose);
        self::assertSame($purpose, $message->purpose);
        self::assertSame(Source::AUTHENTICATION, $message->source);
    }

    /**
     * Rows of `[MFA's purpose, this package's purpose]` for a code of each
     * kind.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Mfa\Enums\Purpose, 1: \SineMacula\Laravel\Iam\Delivery\Enums\Purpose}>
     */
    public static function provideMfaPurposes(): iterable
    {
        yield 'sign-in' => [MfaPurpose::SIGN_IN, Purpose::ADDITIONAL_FACTOR];

        yield 'enrolment' => [MfaPurpose::ENROLLMENT, Purpose::ENROLLMENT];
    }

    /**
     * A message for a code of MFA's says so, and its purpose follows MFA's.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $memberPurpose
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Purpose  $purpose
     * @return void
     */
    #[DataProvider('provideMfaPurposes')]
    public function testThePurposeFollowsAnMfaPurpose(MfaPurpose $memberPurpose, Purpose $purpose): void
    {
        $message = self::message($memberPurpose);

        self::assertSame($memberPurpose, $message->memberPurpose);
        self::assertSame($purpose, $message->purpose);
        self::assertSame(Source::MFA, $message->source);
    }

    /**
     * A password reset link is no code, and no message carries one.
     *
     * @return void
     */
    public function testAPasswordResetLinkIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        self::message(CodePurpose::PASSWORD_RESET_LINK);
    }

    /**
     * Rows of `[application, type, destination, message]`, each with one of
     * them blank.
     *
     * @return iterable<string, array{0: string, 1: string, 2: string, 3: string}>
     */
    public static function provideBlankDetails(): iterable
    {
        yield 'no application' => ['', 'email', self::ADDRESS, 'application'];

        yield 'a blank application' => [' ', 'email', self::ADDRESS, 'application'];

        yield 'no type' => [self::APPLICATION, '', self::ADDRESS, 'type'];

        yield 'a blank type' => [self::APPLICATION, "\t", self::ADDRESS, 'type'];

        yield 'no destination' => [self::APPLICATION, 'email', '', 'destination'];

        yield 'a blank destination' => [self::APPLICATION, 'email', '  ', 'destination'];
    }

    /**
     * A message must name its application, its destination's type and its
     * destination.
     *
     * @param  string  $application
     * @param  string  $type
     * @param  string  $destination
     * @param  string  $missing
     * @return void
     */
    #[DataProvider('provideBlankDetails')]
    public function testABlankDetailIsRefused(string $application, string $type, string $destination, string $missing): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($missing);

        new CodeMessage($application, CodePurpose::SIGN_IN, Channel::EMAIL, $type, $destination, new Secret(self::CODE), CarbonImmutable::now(), new GenericUser(['id' => 1]));
    }

    /**
     * A message made from `laravel-authentication`'s carries its guard, its
     * purpose, its identifier type and identifier, its code itself, its expiry
     * and its identity, on the channel given, and names no factor.
     *
     * @return void
     */
    public function testAMessageFromAuthenticationCarriesItsDetails(): void
    {
        $identity  = \Mockery::mock(Identity::class);
        $code      = new Secret(self::CODE);
        $expiresAt = CarbonImmutable::parse('2026-11-05 12:10:00');
        $source    = new OneTimeCodeMessage(self::APPLICATION, CodePurpose::VERIFICATION, 'phone', self::NUMBER, $code, $expiresAt, $identity);

        $message = CodeMessage::fromAuthentication($source, Channel::SMS);

        self::assertSame(self::APPLICATION, $message->application);
        self::assertSame(CodePurpose::VERIFICATION, $message->memberPurpose);
        self::assertSame(Purpose::VERIFICATION, $message->purpose);
        self::assertSame(Source::AUTHENTICATION, $message->source);
        self::assertSame(Channel::SMS, $message->channel);
        self::assertSame('phone', $message->type);
        self::assertSame(self::NUMBER, $message->destination());
        self::assertSame($code, $message->code);
        self::assertSame($expiresAt, $message->expiresAt);
        self::assertSame($identity, $message->recipient());
        self::assertNull($message->factor);
    }

    /**
     * A message made from MFA's carries its application, its purpose, its
     * factor's type and destination, its code revealed into a secret of its
     * own, its expiry, its recipient and its factor's summary, on the channel
     * given.
     *
     * @return void
     */
    public function testAMessageFromMfaCarriesItsDetails(): void
    {
        $recipient = \Mockery::mock(MultiFactorAuthenticatable::class);
        $expiresAt = CarbonImmutable::parse('2026-11-05 12:10:00');
        $factor    = self::factor();
        $source    = new MfaCodeMessage(self::APPLICATION, MfaPurpose::ENROLLMENT, 'email', self::ADDRESS, new RevealedSecret(self::CODE), $expiresAt, $recipient, $factor);

        $message = CodeMessage::fromMfa($source, Channel::EMAIL);

        self::assertSame(self::APPLICATION, $message->application);
        self::assertSame(MfaPurpose::ENROLLMENT, $message->memberPurpose);
        self::assertSame(Purpose::ENROLLMENT, $message->purpose);
        self::assertSame(Source::MFA, $message->source);
        self::assertSame(Channel::EMAIL, $message->channel);
        self::assertSame('email', $message->type);
        self::assertSame(self::ADDRESS, $message->destination());
        self::assertSame(self::CODE, $message->code->reveal());
        self::assertSame($expiresAt, $message->expiresAt);
        self::assertSame($recipient, $message->recipient());
        self::assertSame($factor, $message->factor);
    }

    /**
     * Neither `print_r()` nor `var_export()` shows the code, the destination or
     * the recipient; a dump shows the placeholder in their place, and the rest
     * as it is.
     *
     * @return void
     */
    public function testADumpShowsNeitherTheCodeTheDestinationNorTheRecipient(): void
    {
        $message = self::message();

        $printed  = print_r($message, true);
        $exported = var_export($message, true);

        foreach ([$printed, $exported] as $output) {
            self::assertStringNotContainsString(self::CODE, $output);
            self::assertStringNotContainsString(self::ADDRESS, $output);
            self::assertStringNotContainsString('person-recipient', $output);
        }

        self::assertStringContainsString(CodeMessage::REDACTED, $printed);
        self::assertStringContainsString(self::APPLICATION, $printed);

        self::assertSame(
            ['application', 'purpose', 'memberPurpose', 'source', 'channel', 'type', 'destination', 'code', 'expiresAt', 'recipient', 'factor'],
            array_keys($message->__debugInfo()),
        );
        self::assertSame(CodeMessage::REDACTED, $message->__debugInfo()['destination']);
        self::assertSame(CodeMessage::REDACTED, $message->__debugInfo()['code']);
        self::assertSame(CodeMessage::REDACTED, $message->__debugInfo()['recipient']);
    }

    /**
     * A message refuses to be serialised, so it is never queued or cached by
     * accident.
     *
     * @return void
     */
    public function testAMessageRefusesToBeSerialised(): void
    {
        $this->expectException(SecretNotRevealedException::class);
        $this->expectExceptionMessage('serialised');

        serialize(self::message());
    }

    /**
     * A message refuses to be unserialised, so none is ever restored from a
     * payload.
     *
     * @return void
     */
    public function testAMessageRefusesToBeUnserialised(): void
    {
        $this->expectException(SecretNotRevealedException::class);
        $this->expectExceptionMessage('unserialised');

        unserialize(sprintf('O:%d:"%s":0:{}', strlen(CodeMessage::class), CodeMessage::class));
    }

    /**
     * A message cannot be encoded as JSON, since its code refuses, so it is
     * never sent as data by accident.
     *
     * @return void
     */
    public function testAMessageRefusesToBeEncodedAsJson(): void
    {
        $this->expectException(SecretNotRevealedException::class);
        $this->expectExceptionMessage('encoded as JSON');

        json_encode(self::message(), JSON_THROW_ON_ERROR);
    }

    /**
     * A message for the code, to the email address, for the purpose given.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose|\SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @return \SineMacula\Laravel\Iam\Delivery\CodeMessage
     */
    private static function message(CodePurpose|MfaPurpose $purpose = CodePurpose::SIGN_IN): CodeMessage
    {
        return new CodeMessage(
            self::APPLICATION,
            $purpose,
            Channel::EMAIL,
            'email',
            self::ADDRESS,
            new Secret(self::CODE),
            CarbonImmutable::parse('2026-11-05 12:10:00'),
            new GenericUser(['id' => 'person-recipient']),
        );
    }

    /**
     * A summary of a confirmed SMS factor, its destination masked.
     *
     * @return \SineMacula\Laravel\Mfa\Factors\FactorSummary
     */
    private static function factor(): FactorSummary
    {
        return new FactorSummary('factor-1', 'sms', 'Phone', '+44•••••••123', FactorStatus::CONFIRMED, true, null);
    }
}
