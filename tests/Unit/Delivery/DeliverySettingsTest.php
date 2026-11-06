<?php

declare(strict_types = 1);

namespace Tests\Unit\Delivery;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose;
use SineMacula\Laravel\Iam\Contracts\EmailGateway;
use SineMacula\Laravel\Iam\Contracts\SmsGateway;
use SineMacula\Laravel\Iam\Delivery\DeliverySettings;
use SineMacula\Laravel\Iam\Delivery\Enums\Channel;
use SineMacula\Laravel\Iam\Exceptions\DeliveryNotConfiguredException;
use SineMacula\Laravel\Iam\Testing\FakeEmailGateway;
use SineMacula\Laravel\Iam\Testing\FakeSmsGateway;

/**
 * Unit tests for resolving the application's gateways and the channel each code
 * goes out on (IAM-3.13): the application's binding of a gateway wins over the
 * class it names, a gateway neither bound nor named, or named by something that
 * is no gateway of its channel, fails closed, and a code of
 * `laravel-authentication`'s goes out on the channel `iam.delivery.types` maps
 * its identifier type to, a factor's code on its own channel.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DeliverySettings::class)]
final class DeliverySettingsTest extends TestCase
{
    /** @var \Illuminate\Container\Container The container gateways are bound and built in. */
    private Container $container;

    /** @var \Illuminate\Config\Repository The configuration the settings read. */
    private Repository $config;

    /**
     * Start each test with an empty container and the shipped delivery
     * configuration.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->container = new Container;
        $this->config    = new Repository(['iam' => ['delivery' => ['email' => null, 'sms' => null, 'types' => ['email' => 'email', 'phone' => 'sms']]]]);
    }

    /**
     * The application's binding of a gateway wins over the class it names.
     *
     * @return void
     */
    public function testTheApplicationsBindingWinsOverTheClassItNames(): void
    {
        $bound = new FakeSmsGateway;

        $this->container->instance(SmsGateway::class, $bound);
        $this->config->set('iam.delivery.sms', FakeSmsGateway::class);

        self::assertSame($bound, $this->settings()->gateway(Channel::SMS));
    }

    /**
     * A gateway the application names, and does not bind, is built by the
     * container, afresh for each code.
     *
     * @return void
     */
    public function testANamedGatewayIsBuiltForEachCode(): void
    {
        $this->config->set('iam.delivery.email', FakeEmailGateway::class);

        $first = $this->settings()->gateway(Channel::EMAIL);

        self::assertInstanceOf(FakeEmailGateway::class, $first);
        self::assertNotSame($first, $this->settings()->gateway(Channel::EMAIL));
    }

    /**
     * Rows of `[the class iam.delivery.{channel} names, the channel]` for a
     * gateway neither bound nor named.
     *
     * @return iterable<string, array{0: mixed, 1: \SineMacula\Laravel\Iam\Delivery\Enums\Channel}>
     */
    public static function provideMissingGateways(): iterable
    {
        yield 'no email gateway' => [null, Channel::EMAIL];

        yield 'a blank sms gateway' => ['  ', Channel::SMS];

        yield 'an sms gateway that is no text' => [['App\Sms'], Channel::SMS];
    }

    /**
     * A gateway neither bound nor named fails closed, naming its key.
     *
     * @param  mixed  $named
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Channel  $channel
     * @return void
     */
    #[DataProvider('provideMissingGateways')]
    public function testAGatewayNeitherBoundNorNamedFailsClosed(mixed $named, Channel $channel): void
    {
        $this->config->set('iam.delivery.' . $channel->value, $named);

        try {
            $this->settings()->gateway($channel);
        } catch (DeliveryNotConfiguredException $exception) {
            self::assertSame($channel, $exception->channel);
            self::assertStringContainsString('named in iam.delivery.' . $channel->value, $exception->getMessage());

            return;
        }

        self::fail('A gateway neither bound nor named must fail closed.');
    }

    /**
     * Rows of `[the class iam.delivery.{channel} names, the channel]` for a
     * gateway named by something that is no gateway of its channel.
     *
     * @return iterable<string, array{0: string, 1: \SineMacula\Laravel\Iam\Delivery\Enums\Channel}>
     */
    public static function provideGatewaysThatAreNone(): iterable
    {
        yield 'a class that does not exist' => ['App\Delivery\Missing', Channel::EMAIL];

        yield 'a class that is no gateway' => [\stdClass::class, Channel::SMS];

        yield 'the contract itself' => [EmailGateway::class, Channel::EMAIL];

        yield 'the other channel\'s gateway' => [FakeEmailGateway::class, Channel::SMS];
    }

    /**
     * A gateway named by something that is no gateway of its channel fails
     * closed, naming the key and what it names.
     *
     * @param  string  $named
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Channel  $channel
     * @return void
     */
    #[DataProvider('provideGatewaysThatAreNone')]
    public function testAGatewayNamedByWhatIsNoneFailsClosed(string $named, Channel $channel): void
    {
        $this->config->set('iam.delivery.' . $channel->value, $named);

        try {
            $this->settings()->gateway($channel);
        } catch (DeliveryNotConfiguredException $exception) {
            self::assertSame($channel, $exception->channel);
            self::assertStringContainsString('iam.delivery.' . $channel->value . ' names [' . $named . ']', $exception->getMessage());

            return;
        }

        self::fail('A gateway named by what is no gateway of its channel must fail closed.');
    }

    /**
     * Rows of `[the channel, the gateway its contract is bound to]` for a
     * binding that is no gateway of its channel.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Iam\Delivery\Enums\Channel, 1: object}>
     */
    public static function provideBindingsThatAreNone(): iterable
    {
        yield 'the email contract bound to an sms gateway' => [Channel::EMAIL, new FakeSmsGateway];

        yield 'the sms contract bound to an email gateway' => [Channel::SMS, new FakeEmailGateway];

        yield 'the sms contract bound to no gateway' => [Channel::SMS, new \stdClass];
    }

    /**
     * A contract the application binds to what is no gateway of its channel
     * fails closed, blaming the binding, not the configuration key it leaves
     * empty.
     *
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Channel  $channel
     * @param  object  $bound
     * @return void
     */
    #[DataProvider('provideBindingsThatAreNone')]
    public function testABindingThatIsNoGatewayOfItsChannelFailsClosed(Channel $channel, object $bound): void
    {
        $contract = $channel === Channel::EMAIL ? EmailGateway::class : SmsGateway::class;

        $this->container->instance($contract, $bound);

        try {
            $this->settings()->gateway($channel);
        } catch (DeliveryNotConfiguredException $exception) {
            self::assertSame($channel, $exception->channel);
            self::assertSame(
                'The container binding of ' . $contract . ' resolves to [' . $bound::class . '], which is no gateway of the '
                . $channel->value . ' channel, so the code cannot be delivered: bind it to a class implementing ' . $contract . '.',
                $exception->getMessage(),
            );

            return;
        }

        self::fail('A binding that is no gateway of its channel must fail closed.');
    }

    /**
     * A gateway the application names, and binds by that name to what is no
     * gateway of its channel, fails closed, blaming that binding, not the class
     * the key names.
     *
     * @return void
     */
    public function testANamedGatewayBoundToWhatIsNoGatewayOfItsChannelFailsClosed(): void
    {
        $this->config->set('iam.delivery.sms', FakeSmsGateway::class);
        $this->container->instance(FakeSmsGateway::class, new FakeEmailGateway);

        try {
            $this->settings()->gateway(Channel::SMS);
        } catch (DeliveryNotConfiguredException $exception) {
            self::assertSame(Channel::SMS, $exception->channel);
            self::assertSame(
                'The container binding of ' . FakeSmsGateway::class . ' resolves to [' . FakeEmailGateway::class . '], which is no gateway'
                . ' of the sms channel, so the code cannot be delivered: bind it to a class implementing ' . SmsGateway::class . '.',
                $exception->getMessage(),
            );

            return;
        }

        self::fail('A named gateway bound to what is no gateway of its channel must fail closed.');
    }

    /**
     * Rows of `[purpose, type, channel]` for a code the shipped routes send.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose, 1: string, 2: \SineMacula\Laravel\Iam\Delivery\Enums\Channel}>
     */
    public static function provideRoutedCodes(): iterable
    {
        yield 'a sign-in code to an address' => [CodePurpose::SIGN_IN, 'email', Channel::EMAIL];

        yield 'a sign-in code to a phone' => [CodePurpose::SIGN_IN, 'phone', Channel::SMS];

        yield 'a verification code to a phone' => [CodePurpose::VERIFICATION, 'phone', Channel::SMS];

        yield 'a password reset code to an address' => [CodePurpose::PASSWORD_RESET, 'email', Channel::EMAIL];

        yield 'an identifier change code to a phone' => [CodePurpose::CHANGE_IDENTIFIER, 'phone', Channel::SMS];

        yield 'a further factor\'s sms code' => [CodePurpose::MFA, 'sms', Channel::SMS];

        yield 'a further factor\'s email code' => [CodePurpose::MFA, 'email', Channel::EMAIL];

        yield 'an enrolment\'s sms code' => [CodePurpose::ENROLLMENT, 'sms', Channel::SMS];
    }

    /**
     * A code goes out on the channel its identifier type routes to, or a
     * factor's code on its own channel.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose  $purpose
     * @param  string  $type
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Channel  $channel
     * @return void
     */
    #[DataProvider('provideRoutedCodes')]
    public function testACodeGoesOutOnTheChannelItRoutesTo(CodePurpose $purpose, string $type, Channel $channel): void
    {
        self::assertSame($channel, $this->settings()->channelFor($purpose, $type));
    }

    /**
     * The routes are the application's: a type of its own goes where it maps
     * it, and the shipped routes are read only when it holds none.
     *
     * @return void
     */
    public function testTheRoutesAreTheApplications(): void
    {
        $this->config->set('iam.delivery.types', ['username' => 'email', 'phone' => 'email']);

        self::assertSame(Channel::EMAIL, $this->settings()->channelFor(CodePurpose::SIGN_IN, 'username'));
        self::assertSame(Channel::EMAIL, $this->settings()->channelFor(CodePurpose::VERIFICATION, 'phone'));

        $this->config->set('iam.delivery', ['email' => null, 'sms' => null]);

        self::assertSame(Channel::SMS, $this->settings()->channelFor(CodePurpose::VERIFICATION, 'phone'));
    }

    /**
     * Rows of `[routes, purpose, type]` for a code that routes to no channel.
     *
     * @return iterable<string, array{0: mixed, 1: \SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose, 2: string}>
     */
    public static function provideUnroutedCodes(): iterable
    {
        $shipped = ['email' => 'email', 'phone' => 'sms'];

        yield 'a type the routes do not map' => [$shipped, CodePurpose::SIGN_IN, 'username'];

        yield 'a channel kind as an identifier type' => [$shipped, CodePurpose::VERIFICATION, 'sms'];

        yield 'a further factor\'s code of an identifier type' => [$shipped, CodePurpose::MFA, 'phone'];

        yield 'an enrolment\'s code of an identifier type' => [$shipped, CodePurpose::ENROLLMENT, 'phone'];

        yield 'a route to a gateway this package does not know' => [['phone' => 'fax'], CodePurpose::SIGN_IN, 'phone'];

        yield 'a route that is no text' => [['phone' => ['sms']], CodePurpose::SIGN_IN, 'phone'];

        yield 'routes that are no map' => ['sms', CodePurpose::SIGN_IN, 'phone'];

        yield 'no routes at all' => [[], CodePurpose::SIGN_IN, 'email'];
    }

    /**
     * A code that routes to no channel fails closed, naming its type.
     *
     * @param  mixed  $types
     * @param  \SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose  $purpose
     * @param  string  $type
     * @return void
     */
    #[DataProvider('provideUnroutedCodes')]
    public function testACodeThatRoutesNowhereFailsClosed(mixed $types, CodePurpose $purpose, string $type): void
    {
        $this->config->set('iam.delivery.types', $types);

        try {
            $this->settings()->channelFor($purpose, $type);
        } catch (DeliveryNotConfiguredException $exception) {
            self::assertSame($type, $exception->type);
            self::assertStringContainsString('iam.delivery.types', $exception->getMessage());

            return;
        }

        self::fail('A code that routes to no channel must fail closed.');
    }

    /**
     * The settings under test, over the test's container and configuration.
     *
     * @return \SineMacula\Laravel\Iam\Delivery\DeliverySettings
     */
    private function settings(): DeliverySettings
    {
        return new DeliverySettings($this->container, $this->config);
    }
}
