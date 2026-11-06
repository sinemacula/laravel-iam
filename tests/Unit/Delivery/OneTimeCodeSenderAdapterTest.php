<?php

declare(strict_types = 1);

namespace Tests\Unit\Delivery;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodeMessage;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Iam\Delivery\DeliverySettings;
use SineMacula\Laravel\Iam\Delivery\Enums\Channel;
use SineMacula\Laravel\Iam\Delivery\Enums\Purpose;
use SineMacula\Laravel\Iam\Delivery\Enums\Source;
use SineMacula\Laravel\Iam\Delivery\OneTimeCodeSenderAdapter;
use SineMacula\Laravel\Iam\Exceptions\DeliveryNotConfiguredException;
use SineMacula\Laravel\Iam\Testing\FakeEmailGateway;
use SineMacula\Laravel\Iam\Testing\FakeSmsGateway;

/**
 * Unit tests for `laravel-authentication`'s one-time code sender pointed at the
 * application's gateways (IAM-3.13): each code reaches the gateway its
 * identifier type routes to, or a factor's code the gateway of its own channel,
 * as this package's one message, and a code that routes nowhere, or to a
 * gateway that is missing, reaches no gateway and throws, as does a gateway's
 * own failure, so `laravel-authentication`'s delivery job fails.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OneTimeCodeSenderAdapter::class)]
final class OneTimeCodeSenderAdapterTest extends TestCase
{
    /** @var string The guard every code is issued on. */
    private const string GUARD = 'api';

    /** @var string The code every message carries. */
    private const string CODE = '615243';

    /** @var \Illuminate\Container\Container The container the gateways are bound in. */
    private Container $container;

    /** @var \Illuminate\Config\Repository The configuration naming the gateways and the routes. */
    private Repository $config;

    /** @var \SineMacula\Laravel\Iam\Testing\FakeEmailGateway The application's email gateway. */
    private FakeEmailGateway $email;

    /** @var \SineMacula\Laravel\Iam\Testing\FakeSmsGateway The application's SMS gateway. */
    private FakeSmsGateway $sms;

    /**
     * Bind a fake of each gateway, with the shipped routes.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->container = new Container;
        $this->config    = new Repository(['iam' => ['delivery' => ['email' => null, 'sms' => null, 'types' => ['email' => 'email', 'phone' => 'sms']]]]);
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
     * Rows of `[purpose, type, channel]` for a code of each kind
     * `laravel-authentication` delivers.
     *
     * @return iterable<string, array{\SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose, string, \SineMacula\Laravel\Iam\Delivery\Enums\Channel}>
     */
    public static function provideCodes(): iterable
    {
        yield 'a sign-in code to a phone' => [CodePurpose::SIGN_IN, 'phone', Channel::SMS];

        yield 'a sign-in code to an address' => [CodePurpose::SIGN_IN, 'email', Channel::EMAIL];

        yield 'a verification code to an address' => [CodePurpose::VERIFICATION, 'email', Channel::EMAIL];

        yield 'a password reset code to a phone' => [CodePurpose::PASSWORD_RESET, 'phone', Channel::SMS];

        yield 'an identifier change code to an address' => [CodePurpose::CHANGE_IDENTIFIER, 'email', Channel::EMAIL];

        yield 'a further factor\'s sms code' => [CodePurpose::MFA, 'sms', Channel::SMS];

        yield 'an enrolment\'s email code' => [CodePurpose::ENROLLMENT, 'email', Channel::EMAIL];
    }

    /**
     * Each code reaches the one gateway it routes to, once, as this package's
     * message: the guard as the application, both purposes, the member, the
     * type, the destination, the very code, its expiry, the recipient, and no
     * factor.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose  $purpose
     * @param  string  $type
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Channel  $channel
     * @return void
     */
    #[DataProvider('provideCodes')]
    public function testEachCodeReachesTheGatewayItRoutesTo(CodePurpose $purpose, string $type, Channel $channel): void
    {
        $source = $this->message($purpose, $type);

        $this->adapter()->send($source);

        [$gateway, $other] = $channel === Channel::SMS ? [$this->sms, $this->email] : [$this->email, $this->sms];

        self::assertSame([], $other->sent());
        self::assertCount(1, $gateway->sent());

        $message = $gateway->sent()[0];

        self::assertSame(self::GUARD, $message->application);
        self::assertSame($purpose, $message->memberPurpose);
        self::assertSame(Purpose::fromAuthentication($purpose), $message->purpose);
        self::assertSame(Source::AUTHENTICATION, $message->source);
        self::assertSame($channel, $message->channel);
        self::assertSame($type, $message->type);
        self::assertSame($source->identifier, $message->destination());
        self::assertSame($source->code, $message->code);
        self::assertSame($source->expiresAt, $message->expiresAt);
        self::assertSame($source->identity, $message->recipient());
        self::assertNull($message->factor);
    }

    /**
     * A code whose type routes to no channel reaches no gateway, and throws.
     *
     * @return void
     */
    public function testACodeThatRoutesNowhereReachesNoGateway(): void
    {
        $this->config->set('iam.delivery.types', ['email' => 'email']);

        $this->expectException(DeliveryNotConfiguredException::class);

        try {
            $this->adapter()->send($this->message(CodePurpose::SIGN_IN, 'phone'));
        } finally {
            self::assertSame([], [...$this->sms->sent(), ...$this->email->sent()]);
        }
    }

    /**
     * A code routed to a gateway the application has neither bound nor named
     * throws.
     *
     * @return void
     */
    public function testACodeRoutedToAMissingGatewayThrows(): void
    {
        $this->container->forgetInstance(FakeSmsGateway::GATEWAY);

        $this->expectException(DeliveryNotConfiguredException::class);

        $this->adapter()->send($this->message(CodePurpose::MFA, 'sms'));
    }

    /**
     * A gateway's own failure reaches `laravel-authentication`'s delivery job,
     * which fails, as it is.
     *
     * @return void
     */
    public function testAGatewaysFailureReachesTheDeliveryJob(): void
    {
        $failure = new \RuntimeException('The provider refused the message.');

        $this->email->failNext($failure);

        try {
            $this->adapter()->send($this->message(CodePurpose::VERIFICATION, 'email'));
        } catch (\RuntimeException $exception) {
            self::assertSame($failure, $exception);
            self::assertSame([], $this->email->sent());

            return;
        }

        self::fail('A gateway\'s failure must reach the delivery job.');
    }

    /**
     * The adapter under test, over the test's container and configuration.
     *
     * @return \SineMacula\Laravel\Iam\Delivery\OneTimeCodeSenderAdapter
     */
    private function adapter(): OneTimeCodeSenderAdapter
    {
        return new OneTimeCodeSenderAdapter(new DeliverySettings($this->container, $this->config));
    }

    /**
     * A code of `laravel-authentication`'s for the purpose, to a destination of
     * the type.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose  $purpose
     * @param  string  $type
     * @return \SineMacula\Laravel\Authentication\Codes\OneTimeCodeMessage
     */
    private function message(CodePurpose $purpose, string $type): OneTimeCodeMessage
    {
        $destination = $type === 'email' ? 'ada@example.test' : '+447700900123';
        $expiresAt   = CarbonImmutable::parse('2026-11-05 12:10:00');

        return new OneTimeCodeMessage(self::GUARD, $purpose, $type, $destination, new Secret(self::CODE), $expiresAt, \Mockery::mock(Identity::class));
    }
}
