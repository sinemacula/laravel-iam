<?php

declare(strict_types = 1);

namespace Tests\Unit\Delivery;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Delivery\DeliverySettings;
use SineMacula\Laravel\Iam\Delivery\Enums\Channel;
use SineMacula\Laravel\Iam\Delivery\Enums\Purpose;
use SineMacula\Laravel\Iam\Delivery\Enums\Source;
use SineMacula\Laravel\Iam\Exceptions\DeliveryNotConfiguredException;
use SineMacula\Laravel\Iam\Testing\FakeEmailGateway;
use SineMacula\Laravel\Iam\Testing\FakeSmsGateway;
use SineMacula\Laravel\Mfa\Codes\CodeMessage as MfaCodeMessage;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\SmsSender;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Enums\Purpose as MfaPurpose;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;

/**
 * What MFA's SMS and email senders pointed at the application's gateways must
 * do (IAM-3.13), run against each: each of MFA's codes reaches the gateway of
 * the sender's channel, once, as this package's one message, its code revealed
 * into a secret of the message's own and its factor's summary kept, and a
 * gateway that is missing, or fails, throws, so MFA rolls the code back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
abstract class MfaSenderAdapterTestCase extends TestCase
{
    /** @var string The code every message carries. */
    private const string CODE = '274913';

    /** @var string The application every code is for. */
    private const string APPLICATION = 'api';

    /** @var \Illuminate\Container\Container The container the gateways are bound in. */
    private Container $container;

    /** @var \SineMacula\Laravel\Iam\Testing\FakeEmailGateway The application's email gateway. */
    private FakeEmailGateway $email;

    /** @var \SineMacula\Laravel\Iam\Testing\FakeSmsGateway The application's SMS gateway. */
    private FakeSmsGateway $sms;

    /**
     * Bind a fake of each gateway.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->container = new Container;
        $this->email     = FakeEmailGateway::fake($this->container);
        $this->sms       = FakeSmsGateway::fake($this->container);
    }

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
     * Rows of `[MFA's purpose, this package's purpose]` for a code of each kind
     * MFA sends.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Mfa\Enums\Purpose, 1: \SineMacula\Laravel\Iam\Delivery\Enums\Purpose}>
     */
    public static function provideCodes(): iterable
    {
        yield 'a sign-in\'s code' => [MfaPurpose::SIGN_IN, Purpose::ADDITIONAL_FACTOR];

        yield 'a reauthentication\'s code' => [MfaPurpose::REAUTHENTICATE, Purpose::ADDITIONAL_FACTOR];

        yield 'a step-up\'s code' => [MfaPurpose::STEP_UP, Purpose::ADDITIONAL_FACTOR];

        yield 'an enrolment\'s code' => [MfaPurpose::ENROLLMENT, Purpose::ENROLLMENT];
    }

    /**
     * Each code reaches the gateway of its sender's channel, once, as this
     * package's message: the application, both purposes, the member, the
     * factor's type, the destination, the code revealed into a secret of its
     * own, its expiry, the recipient and the factor's summary.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Purpose  $neutral
     * @return void
     */
    #[DataProvider('provideCodes')]
    public function testEachCodeReachesTheGatewayOfItsChannel(MfaPurpose $purpose, Purpose $neutral): void
    {
        $channel   = static::channel();
        $recipient = \Mockery::mock(MultiFactorAuthenticatable::class);
        $source    = self::message($channel, $purpose, $recipient);

        $this->sender()->send($source);

        [$gateway, $other] = $channel === Channel::SMS ? [$this->sms, $this->email] : [$this->email, $this->sms];

        static::assertSame([], $other->sent());
        static::assertCount(1, $gateway->sent());

        $message = $gateway->sent()[0];

        static::assertSame(self::APPLICATION, $message->application);
        static::assertSame($purpose, $message->memberPurpose);
        static::assertSame($neutral, $message->purpose);
        static::assertSame(Source::MFA, $message->source);
        static::assertSame($channel, $message->channel);
        static::assertSame($channel->value, $message->type);
        static::assertSame($source->destination(), $message->destination());
        static::assertSame(self::CODE, $message->code->reveal());
        static::assertSame($source->expiresAt, $message->expiresAt);
        static::assertSame($recipient, $message->recipient());
        static::assertSame($source->factor, $message->factor);
    }

    /**
     * A sender whose gateway the application has neither bound nor named
     * throws, so MFA keeps no code.
     *
     * @return void
     */
    public function testASenderWithNoGatewayThrows(): void
    {
        $channel = static::channel();

        $this->container->forgetInstance($channel === Channel::SMS ? FakeSmsGateway::GATEWAY : FakeEmailGateway::GATEWAY);

        $this->expectException(DeliveryNotConfiguredException::class);

        $this->sender()->send(self::message($channel, MfaPurpose::STEP_UP, \Mockery::mock(MultiFactorAuthenticatable::class)));
    }

    /**
     * A gateway's own failure reaches MFA as it is, so MFA keeps no code.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGatewaysFailureReachesMfa(): void
    {
        $channel = static::channel();
        $failure = new \RuntimeException('The provider refused the message.');
        $gateway = $channel === Channel::SMS ? $this->sms : $this->email;

        $gateway->failNext($failure);

        try {
            $this->sender()->send(self::message($channel, MfaPurpose::SIGN_IN, \Mockery::mock(MultiFactorAuthenticatable::class)));
        } catch (\RuntimeException $exception) {
            static::assertSame($failure, $exception);
            static::assertSame([], $gateway->sent());

            return;
        }

        static::fail('A gateway\'s failure must reach MFA.');
    }

    /**
     * The channel of the sender under test.
     *
     * @return \SineMacula\Laravel\Iam\Delivery\Enums\Channel
     */
    abstract protected static function channel(): Channel;

    /**
     * The sender under test, resolving its gateway through the settings.
     *
     * @param  \SineMacula\Laravel\Iam\Delivery\DeliverySettings  $settings
     * @return \SineMacula\Laravel\Mfa\Contracts\EmailSender|\SineMacula\Laravel\Mfa\Contracts\SmsSender
     */
    abstract protected function senderOver(DeliverySettings $settings): EmailSender|SmsSender;

    /**
     * The sender under test, pointed at the test's gateways.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\EmailSender|\SineMacula\Laravel\Mfa\Contracts\SmsSender
     */
    private function sender(): EmailSender|SmsSender
    {
        return $this->senderOver(new DeliverySettings($this->container, new Repository));
    }

    /**
     * A code of MFA's on the channel for the purpose, to the recipient.
     *
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Channel  $channel
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $recipient
     * @return \SineMacula\Laravel\Mfa\Codes\CodeMessage
     */
    private static function message(Channel $channel, MfaPurpose $purpose, MultiFactorAuthenticatable $recipient): MfaCodeMessage
    {
        $destination = $channel === Channel::SMS ? '+447700900123' : 'ada@example.test';
        $factor      = new FactorSummary('factor-1', $channel->value, 'Mine', '****', FactorStatus::CONFIRMED, true, null);

        return new MfaCodeMessage(
            self::APPLICATION,
            $purpose,
            $channel->value,
            $destination,
            new RevealedSecret(self::CODE),
            CarbonImmutable::parse('2026-11-05 12:10:00'),
            $recipient,
            $factor,
        );
    }
}
