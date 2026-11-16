<?php

declare(strict_types = 1);

namespace Tests\Integration\Mfa;

use Carbon\CarbonImmutable;
use Illuminate\Container\Container;
use Illuminate\Contracts\Container\Container as ContainerContract;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose;
use SineMacula\Laravel\Authentication\Testing\FakeOneTimeCodeSender;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\CodeSenderAdapter;
use SineMacula\Laravel\Iam\Mfa\Translation\ChannelTranslator;
use SineMacula\Laravel\Iam\Mfa\Translation\ProofTranslator;
use SineMacula\Laravel\Iam\Sso\ConnectionTrust;
use SineMacula\Laravel\Mfa\Codes\CodeMessage;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Drivers\EmailDriver;
use SineMacula\Laravel\Mfa\Drivers\SmsDriver;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Resolvers\Factorless;
use Tests\TestCase;

/**
 * Integration tests for MFA's senders forwarding to the application's sender.
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
     * Rows of `[MFA's purpose, the code's purpose, the proof purpose's value]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Mfa\Enums\Purpose, 1: \SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose, 2: string}>
     */
    public static function providePurposes(): iterable
    {
        yield 'sign-in' => [Purpose::SIGN_IN, CodePurpose::MFA, 'sign_in'];

        yield 'step-up' => [Purpose::STEP_UP, CodePurpose::MFA, 'step_up'];

        yield 'reauthentication' => [Purpose::REAUTHENTICATE, CodePurpose::MFA, 'reauthenticate'];

        yield 'enrolment' => [Purpose::ENROLLMENT, CodePurpose::ENROLLMENT, 'enrollment'];
    }

    /**
     * MFA's code reaches the application's sender with every field intact.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @param  \SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose  $expected
     * @param  string  $proofPurpose
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('providePurposes')]
    public function testTheCodeReachesTheApplicationsSender(Purpose $purpose, CodePurpose $expected, string $proofPurpose): void
    {
        $sender    = FakeOneTimeCodeSender::fake();
        $person    = new Person;
        $expiresAt = CarbonImmutable::now()->addMinutes(10);

        self::adapter($sender)->send(self::message($purpose, $person, $expiresAt));

        $message = $sender->sent()[0] ?? self::fail('Nothing was sent.');

        self::assertSame(1, $sender->count());
        self::assertSame('api', $message->guard);
        self::assertSame($expected, $message->purpose);
        self::assertSame('sms', $message->type);
        self::assertSame('+447700900123', $message->identifier);
        self::assertSame('123456', $message->code->reveal());
        self::assertSame($expiresAt, $message->expiresAt);
        self::assertSame($person, $message->identity);
        self::assertSame($proofPurpose, $message->proofPurpose?->value);
        self::assertSame('factor-1', $message->factor);
    }

    /**
     * Rows of `[the factor type, the driver it is registered on, the channel kind's value]`.
     *
     * @return iterable<string, array{0: string, 1: class-string<\SineMacula\Laravel\Mfa\Drivers\AbstractCodeDriver>, 2: string}>
     */
    public static function provideCustomTypes(): iterable
    {
        yield 'email driver' => ['work_email', EmailDriver::class, 'email'];

        yield 'sms driver' => ['mobile', SmsDriver::class, 'sms'];
    }

    /**
     * A custom-named type is sent under its driver's channel kind.
     *
     * @param  string  $type
     * @param  class-string<\SineMacula\Laravel\Mfa\Drivers\AbstractCodeDriver>  $driver
     * @param  string  $kind
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideCustomTypes')]
    public function testACustomNamedTypeIsSentUnderItsDriversChannelKind(string $type, string $driver, string $kind): void
    {
        Mfa::extend($type, static fn (ContainerContract $app): FactorDriver => $app->make($driver));

        $sender = FakeOneTimeCodeSender::fake();

        self::adapter($sender)->send(self::message(Purpose::SIGN_IN, new Person, CarbonImmutable::now(), $type));

        self::assertSame($kind, ($sender->sent()[0] ?? self::fail('Nothing was sent.'))->type);
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
        $sender = FakeOneTimeCodeSender::fake();

        try {
            self::adapter($sender)->send(self::message(Purpose::STEP_UP, new Factorless, CarbonImmutable::now()));
            self::fail('The recipient was accepted.');
        } catch (UnresolvedReferenceException $exception) {
            self::assertSame(ReferenceKind::IDENTITY, $exception->kind);
            self::assertStringContainsString(Factorless::class, $exception->getMessage());
        }

        self::assertSame(0, $sender->count());
    }

    /**
     * The adapter forwarding to the sender.
     *
     * @param  \SineMacula\Laravel\Authentication\Testing\FakeOneTimeCodeSender  $sender
     * @return \SineMacula\Laravel\Iam\Mfa\CodeSenderAdapter
     */
    private static function adapter(FakeOneTimeCodeSender $sender): CodeSenderAdapter
    {
        return new CodeSenderAdapter($sender, new ProofTranslator(new ChannelTranslator, new ConnectionTrust(new Container)));
    }

    /**
     * A code of MFA's for the recipient, on a factor of the type.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $recipient
     * @param  \Carbon\CarbonImmutable  $expiresAt
     * @param  string  $type
     * @return \SineMacula\Laravel\Mfa\Codes\CodeMessage
     */
    private static function message(Purpose $purpose, MultiFactorAuthenticatable $recipient, CarbonImmutable $expiresAt, string $type = 'sms'): CodeMessage
    {
        $factor = new FactorSummary('factor-1', $type, 'Phone', '+44*******123', FactorStatus::CONFIRMED, true, null);

        return new CodeMessage('api', $purpose, $type, '+447700900123', new RevealedSecret('123456'), $expiresAt, $recipient, $factor);
    }
}
