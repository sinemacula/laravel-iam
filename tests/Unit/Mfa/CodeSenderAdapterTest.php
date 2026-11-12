<?php

declare(strict_types = 1);

namespace Tests\Unit\Mfa;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose;
use SineMacula\Laravel\Authentication\Testing\FakeOneTimeCodeSender;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\CodeSenderAdapter;
use SineMacula\Laravel\Mfa\Codes\CodeMessage;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Resolvers\Factorless;

/**
 * Unit tests for MFA's senders forwarding to the application's sender.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CodeSenderAdapter::class)]
final class CodeSenderAdapterTest extends TestCase
{
    /**
     * Rows of `[MFA's purpose, laravel-authentication's purpose]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Mfa\Enums\Purpose, 1: \SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose}>
     */
    public static function providePurposes(): iterable
    {
        yield 'sign-in' => [Purpose::SIGN_IN, CodePurpose::MFA];

        yield 'step-up' => [Purpose::STEP_UP, CodePurpose::MFA];

        yield 'reauthentication' => [Purpose::REAUTHENTICATE, CodePurpose::MFA];

        yield 'enrolment' => [Purpose::ENROLLMENT, CodePurpose::ENROLLMENT];
    }

    /**
     * MFA's code reaches the application's sender with every field intact.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @param  \SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose  $expected
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('providePurposes')]
    public function testTheCodeReachesTheApplicationsSender(Purpose $purpose, CodePurpose $expected): void
    {
        $sender    = new FakeOneTimeCodeSender;
        $person    = new Person;
        $expiresAt = CarbonImmutable::now()->addMinutes(10);

        (new CodeSenderAdapter($sender))->send(self::message($purpose, $person, $expiresAt));

        $message = $sender->sent()[0] ?? self::fail('Nothing was sent.');

        self::assertSame(1, $sender->count());
        self::assertSame('api', $message->guard);
        self::assertSame($expected, $message->purpose);
        self::assertSame('sms', $message->type);
        self::assertSame('+447700900123', $message->identifier);
        self::assertSame('123456', $message->code->reveal());
        self::assertSame($expiresAt, $message->expiresAt);
        self::assertSame($person, $message->identity);
    }

    /**
     * A recipient that is no identity is refused and nothing is sent.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARecipientThatIsNoIdentityThrows(): void
    {
        $sender = new FakeOneTimeCodeSender;

        try {
            (new CodeSenderAdapter($sender))->send(self::message(Purpose::STEP_UP, new Factorless, CarbonImmutable::now()));
            self::fail('The recipient was accepted.');
        } catch (UnresolvedReferenceException $exception) {
            self::assertSame(ReferenceKind::IDENTITY, $exception->kind);
            self::assertStringContainsString(Factorless::class, $exception->getMessage());
        }

        self::assertSame(0, $sender->count());
    }

    /**
     * An SMS code of MFA's for the recipient.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $recipient
     * @param  \Carbon\CarbonImmutable  $expiresAt
     * @return \SineMacula\Laravel\Mfa\Codes\CodeMessage
     */
    private static function message(Purpose $purpose, MultiFactorAuthenticatable $recipient, CarbonImmutable $expiresAt): CodeMessage
    {
        $factor = new FactorSummary('factor-1', 'sms', 'Phone', '+44*******123', FactorStatus::CONFIRMED, true, null);

        return new CodeMessage('api', $purpose, 'sms', '+447700900123', new RevealedSecret('123456'), $expiresAt, $recipient, $factor);
    }
}
