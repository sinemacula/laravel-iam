<?php

declare(strict_types = 1);

namespace Tests\Feature\Delivery;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Contracts\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\OneTimeCodeSender;
use SineMacula\Laravel\Iam\Bindings\BindingOutcome;
use SineMacula\Laravel\Iam\Bindings\Enums\Lifetime;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Iam\Contracts\EmailGateway;
use SineMacula\Laravel\Iam\Contracts\SmsGateway;
use SineMacula\Laravel\Iam\Delivery\DeliverySeams;
use SineMacula\Laravel\Iam\Delivery\EmailSenderAdapter;
use SineMacula\Laravel\Iam\Delivery\Enums\Channel;
use SineMacula\Laravel\Iam\Delivery\OneTimeCodeSenderAdapter;
use SineMacula\Laravel\Iam\Delivery\SmsSenderAdapter;
use SineMacula\Laravel\Iam\Mfa\ChallengeGatewayAdapter;
use SineMacula\Laravel\Mfa\Codes\NullEmailSender;
use SineMacula\Laravel\Mfa\Codes\NullSmsSender;
use SineMacula\Laravel\Mfa\Codes\PackageChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;
use SineMacula\Laravel\Mfa\Contracts\SmsSender;
use SineMacula\Laravel\Mfa\Exceptions\InvalidConfigurationException;
use Tests\Concerns\PermutesProviderOrder;
use Tests\TestCase;

/**
 * Feature tests for the seams every member's codes are delivered through
 * (IAM-3.13): MFA's sender of a channel is pointed at that channel's gateway
 * while it is named or bound, `laravel-authentication`'s one-time code sender
 * once every gateway `iam.delivery.types` routes to is, and a gateway the
 * application has neither named nor bound binds nothing (IAM-1.3), in every
 * provider order; an application's own sender is kept or wins as the binding
 * rule says (IAM-8.4). MFA's codes take `laravel-authentication`'s path only
 * while it delivers them, so a configuration that cannot deliver a type MFA
 * offers is refused by MFA's own boot check rather than booting.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DeliverySeams::class)]
final class DeliverySeamsTest extends TestCase
{
    use PermutesProviderOrder;

    /** @var array<class-string, class-string> Each seam, with the adapter bound over it. */
    private const array ADAPTERS = [
        OneTimeCodeSender::class => OneTimeCodeSenderAdapter::class,
        SmsSender::class         => SmsSenderAdapter::class,
        EmailSender::class       => EmailSenderAdapter::class,
    ];

    /** @var array<class-string, list<class-string>> Each seam, with its member's own defaults. */
    private const array MEMBER_DEFAULTS = [
        OneTimeCodeSender::class => [],
        SmsSender::class         => [NullSmsSender::class],
        EmailSender::class       => [NullEmailSender::class],
    ];

    /** @var string A class name the application names a gateway by; the switches read only that one is named. */
    private const string GATEWAY = 'App\Delivery\Gateway';

    /** @var array<string, mixed> The delivery configuration this package ships, which the application's replaces as a whole. */
    private const array DEFAULT_DELIVERY = ['email' => null, 'sms' => null, 'types' => ['email' => 'email', 'phone' => 'sms']];

    /** @var array<string, mixed> The delivery configuration the application holds before any provider registers, over the shipped one. */
    private array $delivery = [];

    /** @var list<string> The factor types the MFA application offers. */
    private array $offered = ['totp'];

    /**
     * Every adapter is bound over its member's default once both gateways are
     * named, in every provider order.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testEveryAdapterIsBoundOnceBothGatewaysAreNamedInEveryProviderOrder(array $providers): void
    {
        $this->delivery = ['email' => self::GATEWAY, 'sms' => self::GATEWAY];

        $this->bootInOrder($providers);

        $this->assertResolvesTo(self::ADAPTERS);
        $this->assertOutcome(array_keys(self::ADAPTERS), []);
    }

    /**
     * Nothing is bound while no gateway is named or bound: MFA keeps its own
     * senders and `laravel-authentication` its unbound sender, in every
     * provider order.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testNothingIsBoundWhileNoGatewayIsNamed(array $providers): void
    {
        $this->bootInOrder($providers);

        $this->assertResolvesTo([SmsSender::class => NullSmsSender::class, EmailSender::class => NullEmailSender::class]);
        self::assertFalse($this->application()->bound(OneTimeCodeSender::class));
        $this->assertOutcome([], []);
    }

    /**
     * A gateway bound in the container before any provider registers counts as
     * named, in every provider order.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testAGatewayBoundBeforeAnyProviderRegistersCountsAsNamed(array $providers): void
    {
        $this->bootInOrder($providers, before: [
            EmailGateway::class => \Mockery::mock(EmailGateway::class),
            SmsGateway::class   => \Mockery::mock(SmsGateway::class),
        ]);

        $this->assertResolvesTo(self::ADAPTERS);
        $this->assertOutcome(array_keys(self::ADAPTERS), []);
    }

    /**
     * MFA's SMS sender is pointed at the SMS gateway once it alone is named,
     * while its email sender and `laravel-authentication`'s one-time code
     * sender, whose default routes reach the email gateway too, stay as they
     * are, and so does MFA's challenge gateway, so MFA's codes go through the
     * SMS sender rather than a one-time code sender that is not bound.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testOnlyTheSmsSenderIsBoundWhileOnlyTheSmsGatewayIsNamed(): void
    {
        $this->delivery = ['sms' => self::GATEWAY];

        $this->reloadApplication();

        $this->assertResolvesTo([
            SmsSender::class        => SmsSenderAdapter::class,
            EmailSender::class      => NullEmailSender::class,
            ChallengeGateway::class => PackageChallengeGateway::class,
        ]);
        self::assertFalse($this->application()->bound(OneTimeCodeSender::class));
        $this->assertOutcome([SmsSender::class], []);
    }

    /**
     * Rows of `[gateway named, factor type offered]`: an application that names
     * one gateway only, with the shipped routes, and offers that gateway's
     * channel as an MFA type.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideOneGateway(): iterable
    {
        yield 'sms' => ['sms', 'sms'];

        yield 'email' => ['email', 'email'];
    }

    /**
     * An application that names one gateway only, keeping the shipped routes,
     * boots with MFA's sender of that channel pointed at it and MFA's own
     * challenge gateway kept, so MFA's codes go through the sender its boot
     * check judged, never through a one-time code sender that is not bound.
     *
     * @param  string  $channel
     * @param  string  $type
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideOneGateway')]
    public function testWithOneGatewayNamedMfaSendsThatChannelsCodesItself(string $channel, string $type): void
    {
        $this->delivery = [$channel => self::GATEWAY];
        $this->offered  = ['totp', $type];

        $this->reloadApplication();

        $sender = $channel === 'sms' ? SmsSender::class : EmailSender::class;

        $this->assertResolvesTo([ChallengeGateway::class => PackageChallengeGateway::class, $sender => self::ADAPTERS[$sender]]);
        self::assertFalse($this->application()->bound(OneTimeCodeSender::class));
    }

    /**
     * Rows of `[delivery configuration, factor types offered]` that cannot
     * deliver a type MFA offers: the shipped routes with only the other
     * channel's gateway named, and routes that reach the email gateway alone,
     * so `laravel-authentication` delivers MFA's codes, while MFA offers SMS.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: list<string>}>
     */
    public static function provideUndeliverableTypes(): iterable
    {
        yield 'email offered, only the sms gateway named' => [['sms' => self::GATEWAY], ['totp', 'email']];

        yield 'sms offered, only the email gateway named' => [['email' => self::GATEWAY], ['totp', 'sms']];

        yield 'sms offered, only email routed and named' => [['email' => self::GATEWAY, 'types' => ['email' => 'email']], ['totp', 'sms']];
    }

    /**
     * A configuration that cannot deliver a type MFA offers is refused at boot
     * by MFA's own check, since the sender it judges is the one the type's
     * codes would go through.
     *
     * @param  array<string, mixed>  $delivery
     * @param  list<string>  $offered
     * @return void
     */
    #[DataProvider('provideUndeliverableTypes')]
    public function testAConfigurationThatCannotDeliverAnOfferedTypeIsRefusedAtBoot(array $delivery, array $offered): void
    {
        $this->delivery = $delivery;
        $this->offered  = $offered;

        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('no ' . ($offered[1] === 'sms' ? 'SMS' : 'email') . ' sender is bound');

        $this->reloadApplication();
    }

    /**
     * Rows of `[delivery configuration, bindings in the container, factor codes
     * routed]`.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: array<class-string, class-string|\Closure(): object>, 2: bool}>
     */
    public static function provideFactorCodeRoutes(): iterable
    {
        $both = ['email' => self::GATEWAY, 'sms' => self::GATEWAY];
        $own  = static fn (): object => \Mockery::mock(SmsSender::class);

        yield 'both named' => [$both, [], true];

        yield 'one named' => [['sms' => self::GATEWAY], [], false];

        yield 'both named, nothing routed' => [[...$both, 'types' => []], [], false];

        yield 'none named, the application\'s one-time code sender' => [[], [OneTimeCodeSender::class => static fn (): object => \Mockery::mock(OneTimeCodeSender::class)], true];

        yield 'both named, MFA\'s own senders' => [$both, [SmsSender::class => NullSmsSender::class, EmailSender::class => NullEmailSender::class], true];

        yield 'both named, this package\'s senders' => [$both, [SmsSender::class => SmsSenderAdapter::class, EmailSender::class => EmailSenderAdapter::class], true];

        yield 'both named, the application\'s SMS sender' => [$both, [SmsSender::class => $own], true];

        yield 'both named, the application\'s email sender' => [$both, [EmailSender::class => static fn (): object => \Mockery::mock(EmailSender::class)], true];

        yield 'none named, the application\'s SMS sender' => [[], [SmsSender::class => $own], false];
    }

    /**
     * MFA's challenge gateway is pointed at `laravel-authentication`'s factor
     * codes exactly while its one-time code sender is bound, the application's
     * or this package's, whoever binds MFA's senders: the adapter judges each
     * code's sender as it sends it.
     *
     * @param  array<string, mixed>  $delivery
     * @param  array<class-string, class-string|\Closure(): object>  $bindings
     * @param  bool  $routed
     * @return void
     */
    #[DataProvider('provideFactorCodeRoutes')]
    public function testFactorCodesAreRoutedOnlyWhileAuthenticationDeliversThem(array $delivery, array $bindings, bool $routed): void
    {
        $container = new Container;

        foreach ($bindings as $abstract => $concrete) {
            $container->bind($abstract, $concrete);
        }

        self::assertSame($routed, (new DeliverySeams($container))->routesFactorCodes(new Repository(['iam' => ['delivery' => $delivery]])));
    }

    /**
     * `laravel-authentication`'s one-time code sender is pointed at the email
     * gateway once it is named and every type routes to it.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheOneTimeCodeSenderIsBoundOnceEveryRoutedGatewayIsNamed(): void
    {
        $this->delivery = ['email' => self::GATEWAY, 'types' => ['email' => 'email']];

        $this->reloadApplication();

        $this->assertResolvesTo([
            OneTimeCodeSender::class => OneTimeCodeSenderAdapter::class,
            EmailSender::class       => EmailSenderAdapter::class,
            ChallengeGateway::class  => ChallengeGatewayAdapter::class,
        ]);
        $this->assertOutcome([OneTimeCodeSender::class, EmailSender::class], []);
    }

    /**
     * An application sender bound before any provider registers is kept over
     * every seam, in every provider order, and MFA's challenge gateway is bound
     * as it is when the senders are bound later: the adapter judges each code's
     * sender as it sends it.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testAnApplicationSenderBoundBeforeAnyProviderRegistersIsKept(array $providers): void
    {
        $this->delivery = ['email' => self::GATEWAY, 'sms' => self::GATEWAY];

        [$bindings, $instances] = self::applicationBindings();

        $this->bootInOrder($providers, before: $bindings);

        $this->assertResolvesToInstances($instances);
        $this->assertResolvesTo([ChallengeGateway::class => ChallengeGatewayAdapter::class]);
        $this->assertOutcome([], array_keys(self::ADAPTERS));
    }

    /**
     * An application sender bound once every provider has registered replaces
     * every adapter, in every provider order, and MFA's challenge gateway is
     * bound as it is when the senders are bound first.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testAnApplicationSenderBoundOnceEveryProviderHasRegisteredWins(array $providers): void
    {
        $this->delivery = ['email' => self::GATEWAY, 'sms' => self::GATEWAY];

        [$bindings, $instances] = self::applicationBindings();

        $this->bootInOrder($providers, after: $bindings);

        $this->assertResolvesToInstances($instances);
        $this->assertResolvesTo([ChallengeGateway::class => ChallengeGatewayAdapter::class]);
        $this->assertOutcome(array_keys(self::ADAPTERS), []);
    }

    /**
     * Rows of `[delivery configuration, one-time code sender on, SMS sender on,
     * email sender on]`.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: bool, 2: bool, 3: bool}>
     */
    public static function provideSwitches(): iterable
    {
        yield 'both named' => [['email' => self::GATEWAY, 'sms' => self::GATEWAY, 'types' => ['email' => 'email', 'phone' => 'sms']], true, true, true];

        yield 'neither named' => [['types' => ['email' => 'email', 'phone' => 'sms']], false, false, false];

        yield 'email named, both routed' => [['email' => self::GATEWAY, 'types' => ['email' => 'email', 'phone' => 'sms']], false, false, true];

        yield 'email named, email routed' => [['email' => self::GATEWAY, 'types' => ['email' => 'email']], true, false, true];

        yield 'sms named, phone routed' => [['sms' => self::GATEWAY, 'types' => ['phone' => 'sms']], true, true, false];

        yield 'a blank name' => [['email' => ' ', 'sms' => '', 'types' => ['email' => 'email']], false, false, false];

        yield 'a name that is not text' => [['email' => true, 'sms' => 1, 'types' => ['email' => 'email']], false, false, false];

        yield 'routes left out, both named' => [['email' => self::GATEWAY, 'sms' => self::GATEWAY], true, true, true];

        yield 'routes left out, email named' => [['email' => self::GATEWAY], false, false, true];

        yield 'no routes' => [['email' => self::GATEWAY, 'sms' => self::GATEWAY, 'types' => []], false, true, true];

        yield 'routes not a map' => [['email' => self::GATEWAY, 'sms' => self::GATEWAY, 'types' => 'email'], false, true, true];

        yield 'a route to an unknown gateway' => [['email' => self::GATEWAY, 'sms' => self::GATEWAY, 'types' => ['email' => 'email', 'fax' => 'fax']], false, true, true];

        yield 'a route that is not text' => [['email' => self::GATEWAY, 'sms' => self::GATEWAY, 'types' => ['email' => ['email']]], false, true, true];
    }

    /**
     * Each sender's binding is on exactly while the gateways it delivers
     * through are named.
     *
     * @param  array<string, mixed>  $delivery
     * @param  bool  $codes
     * @param  bool  $sms
     * @param  bool  $email
     * @return void
     */
    #[DataProvider('provideSwitches')]
    public function testEachBindingIsOnWhileItsGatewaysAreNamed(array $delivery, bool $codes, bool $sms, bool $email): void
    {
        $config   = new Repository(['iam' => ['delivery' => $delivery]]);
        $expected = [OneTimeCodeSender::class => $codes, SmsSender::class => $sms, EmailSender::class => $email];

        foreach ((new DeliverySeams(new Container))->seams($config) as $binding) {

            self::assertNotNull($binding->appliesWhen);
            self::assertSame($expected[$binding->abstract], ($binding->appliesWhen)($config), $binding->abstract);
        }
    }

    /**
     * A gateway is available once named or bound, and each channel's gateway
     * implements its own contract.
     *
     * @return void
     */
    public function testAGatewayIsAvailableOnceNamedOrBound(): void
    {
        $container = new Container;
        $seams     = new DeliverySeams($container);
        $named     = new Repository(['iam' => ['delivery' => ['email' => self::GATEWAY]]]);
        $none      = new Repository;

        self::assertTrue(DeliverySeams::isNamed($named, Channel::EMAIL));
        self::assertFalse(DeliverySeams::isNamed($named, Channel::SMS));
        self::assertTrue($seams->isAvailable($named, Channel::EMAIL));
        self::assertFalse($seams->isAvailable($none, Channel::SMS));

        $container->instance(SmsGateway::class, \Mockery::mock(SmsGateway::class));

        self::assertTrue($seams->isAvailable($none, Channel::SMS));
        self::assertFalse($seams->isAvailable($none, Channel::EMAIL));
        self::assertSame(EmailGateway::class, DeliverySeams::contract(Channel::EMAIL));
        self::assertSame(SmsGateway::class, DeliverySeams::contract(Channel::SMS));
    }

    /**
     * Every binding is transient over its member's default, and none is
     * mandatory.
     *
     * @return void
     */
    public function testEveryBindingIsTransientOverItsMembersDefault(): void
    {
        $bindings = (new DeliverySeams(new Container))->seams(new Repository);

        self::assertSame(self::ADAPTERS, array_combine(
            array_map(static fn (SeamBinding $binding): string => $binding->abstract, $bindings),
            array_map(static fn (SeamBinding $binding): string => $binding->adapter, $bindings),
        ));

        foreach ($bindings as $binding) {
            self::assertSame(Lifetime::TRANSIENT, $binding->lifetime, $binding->abstract);
            self::assertFalse($binding->mandatory, $binding->abstract);
            self::assertSame(self::MEMBER_DEFAULTS[$binding->abstract], $binding->memberDefaults, $binding->abstract);
        }
    }

    /**
     * Load the application's configuration, then the delivery configuration the
     * test holds, set as a whole over the shipped one, as a published
     * configuration file holds it, before any provider registers.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function resolveApplicationConfiguration(mixed $app): void
    {
        parent::resolveApplicationConfiguration($app);

        $app->make('config')->set('iam.delivery', [...self::DEFAULT_DELIVERY, ...$this->delivery]);
    }

    /**
     * The factor types the test offers.
     *
     * @return list<string>
     */
    #[\Override]
    protected function mfaTypes(): array
    {
        return $this->offered;
    }

    /**
     * The application, failing the test when none has booted.
     *
     * @return \Illuminate\Contracts\Foundation\Application
     */
    private function application(): Application
    {
        self::assertInstanceOf(Application::class, $this->app);

        return $this->app;
    }

    /**
     * The application's own binding of every seam, each a closure returning its
     * own instance, with those instances.
     *
     * @return array{0: array<string, \Closure(): object>, 1: array<string, object>}
     */
    private static function applicationBindings(): array
    {
        $bindings  = [];
        $instances = [];

        foreach (array_keys(self::ADAPTERS) as $abstract) {

            $instance = \Mockery::mock($abstract);

            $instances[$abstract] = $instance;
            $bindings[$abstract]  = static fn (): object => $instance;
        }

        return [$bindings, $instances];
    }

    /**
     * Assert each seam resolves to an instance of the given class.
     *
     * @param  array<class-string, class-string>  $expected
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function assertResolvesTo(array $expected): void
    {
        foreach ($expected as $abstract => $concrete) {
            self::assertInstanceOf($concrete, $this->application()->make($abstract), $abstract);
        }
    }

    /**
     * Assert each seam resolves to the given instance.
     *
     * @param  array<string, object>  $expected
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function assertResolvesToInstances(array $expected): void
    {
        foreach ($expected as $abstract => $instance) {
            self::assertSame($instance, $this->application()->make($abstract), $abstract);
        }
    }

    /**
     * Assert the binding rule bound and kept exactly the given seams among the
     * delivery seams, in the order they are declared.
     *
     * @param  list<string>  $bound
     * @param  list<string>  $kept
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function assertOutcome(array $bound, array $kept): void
    {
        $outcome = $this->application()->make(BindingOutcome::class);
        $seams   = array_keys(self::ADAPTERS);

        self::assertInstanceOf(BindingOutcome::class, $outcome);
        self::assertSame($bound, array_values(array_intersect($outcome->bound, $seams)));
        self::assertSame($kept, array_values(array_intersect($outcome->kept, $seams)));
    }
}
