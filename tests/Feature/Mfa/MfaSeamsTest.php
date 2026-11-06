<?php

declare(strict_types = 1);

namespace Tests\Feature\Mfa;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Contracts\Foundation\Application;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Codes\RefuseFactorCodes;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\FactorCodeCounters;
use SineMacula\Laravel\Authentication\Contracts\OneTimeCodeSender;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck as AuthenticationRequirementCheck;
use SineMacula\Laravel\Authentication\Factors\NeverRequireAdditionalFactor;
use SineMacula\Laravel\Authentication\Requirements\MeetNoRequirement;
use SineMacula\Laravel\Iam\Bindings\BindingOutcome;
use SineMacula\Laravel\Iam\Bindings\Enums\Lifetime;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Iam\Delivery\DeliverySeams;
use SineMacula\Laravel\Iam\Delivery\OneTimeCodeSenderAdapter;
use SineMacula\Laravel\Iam\Mfa\AdditionalFactorPolicyAdapter;
use SineMacula\Laravel\Iam\Mfa\ChallengeGatewayAdapter;
use SineMacula\Laravel\Iam\Mfa\FactorChangeGateAdapter;
use SineMacula\Laravel\Iam\Mfa\FactorCodeCountersAdapter;
use SineMacula\Laravel\Iam\Mfa\FirstFactorResolverAdapter;
use SineMacula\Laravel\Iam\Mfa\FreshnessGateAdapter;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use SineMacula\Laravel\Iam\Mfa\PendingCompletionAdapter;
use SineMacula\Laravel\Iam\Mfa\PendingSessionResolverAdapter;
use SineMacula\Laravel\Iam\Mfa\ProofStoreAdapter;
use SineMacula\Laravel\Iam\Mfa\ReauthenticatorAdapter;
use SineMacula\Laravel\Iam\Mfa\RequirementCheckAdapter;
use SineMacula\Laravel\Iam\Mfa\SessionRevokerAdapter;
use SineMacula\Laravel\Iam\Mfa\SessionTransitionAdapter;
use SineMacula\Laravel\Iam\Mfa\StepUpAdapter;
use SineMacula\Laravel\Mfa\Applications\DeclaredFirstFactorResolver;
use SineMacula\Laravel\Mfa\Codes\PackageChallengeGateway;
use SineMacula\Laravel\Mfa\Context\NoPendingSessionResolver;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;
use SineMacula\Laravel\Mfa\Contracts\FactorChangeGate;
use SineMacula\Laravel\Mfa\Contracts\FirstFactorResolver;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Contracts\PendingCompletion;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\Reauthenticator;
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;
use SineMacula\Laravel\Mfa\Contracts\SessionTransition;
use SineMacula\Laravel\Mfa\Contracts\SmsSender;
use SineMacula\Laravel\Mfa\Contracts\StepUp;
use SineMacula\Laravel\Mfa\Http\MiddlewareSessionTransition;
use SineMacula\Laravel\Mfa\Proofs\GenerationSessionRevoker;
use SineMacula\Laravel\Mfa\Proofs\ProofBindings;
use SineMacula\Laravel\Mfa\Proofs\ProofStoreCompletion;
use SineMacula\Laravel\Mfa\Proofs\SessionProofStore;
use SineMacula\Laravel\Mfa\Requirements\ConfiguredFactorChangeGate;
use SineMacula\Laravel\Mfa\Requirements\ConfiguredFreshnessGate;
use SineMacula\Laravel\Mfa\Seams\RefusingReauthenticator;
use Tests\Concerns\PermutesProviderOrder;
use Tests\TestCase;

/**
 * Feature tests for the seams `laravel-authentication` and MFA join through:
 * every adapter replaces its member's default, MFA's closure-bound proof store
 * and `laravel-authentication`'s shared factor code counters included, in every
 * provider order; an application's own binding is kept or wins as the binding
 * rule says (IAM-8.4); and the capability's switch turns every binding off at
 * once. MFA's challenge gateway is pointed at `laravel-authentication`'s factor
 * codes only while that path can deliver them: `laravel-authentication`'s
 * one-time code sender is bound; otherwise MFA keeps its own. Whoever binds
 * MFA's senders, and whenever, the gateway binds alike, since the adapter
 * judges each code's sender as it sends it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MfaSeams::class)]
final class MfaSeamsTest extends TestCase
{
    use PermutesProviderOrder;

    /** @var array<class-string, class-string> Each seam, with the adapter bound over it. */
    private const array ADAPTERS = [
        AdditionalFactorPolicy::class         => AdditionalFactorPolicyAdapter::class,
        AuthenticationRequirementCheck::class => RequirementCheckAdapter::class,
        PendingSessionResolver::class         => PendingSessionResolverAdapter::class,
        PendingCompletion::class              => PendingCompletionAdapter::class,
        StepUp::class                         => StepUpAdapter::class,
        Reauthenticator::class                => ReauthenticatorAdapter::class,
        FreshnessGate::class                  => FreshnessGateAdapter::class,
        FactorChangeGate::class               => FactorChangeGateAdapter::class,
        SessionRevoker::class                 => SessionRevokerAdapter::class,
        SessionTransition::class              => SessionTransitionAdapter::class,
        ProofStore::class                     => ProofStoreAdapter::class,
        FirstFactorResolver::class            => FirstFactorResolverAdapter::class,
        ChallengeGateway::class               => ChallengeGatewayAdapter::class,
        FactorCodeCounters::class             => FactorCodeCountersAdapter::class,
    ];

    /** @var string A class name the application names a gateway by; the switches read only that one is named. */
    private const string GATEWAY = 'App\Delivery\Gateway';

    /** @var array<class-string, class-string> Each seam, with the class its member's own default resolves to. */
    private const array MEMBER_DEFAULTS = [
        AdditionalFactorPolicy::class         => NeverRequireAdditionalFactor::class,
        AuthenticationRequirementCheck::class => MeetNoRequirement::class,
        PendingSessionResolver::class         => NoPendingSessionResolver::class,
        PendingCompletion::class              => ProofStoreCompletion::class,
        StepUp::class                         => ProofStoreCompletion::class,
        Reauthenticator::class                => RefusingReauthenticator::class,
        FreshnessGate::class                  => ConfiguredFreshnessGate::class,
        FactorChangeGate::class               => ConfiguredFactorChangeGate::class,
        SessionRevoker::class                 => GenerationSessionRevoker::class,
        SessionTransition::class              => MiddlewareSessionTransition::class,
        ProofStore::class                     => SessionProofStore::class,
        FirstFactorResolver::class            => DeclaredFirstFactorResolver::class,
        ChallengeGateway::class               => PackageChallengeGateway::class,
        FactorCodeCounters::class             => RefuseFactorCodes::class,
    ];

    /** @var array<string, mixed> The delivery configuration the application holds before any provider registers: both gateways named, unless a test names fewer. */
    private array $delivery = ['email' => self::GATEWAY, 'sms' => self::GATEWAY, 'types' => ['email' => 'email', 'phone' => 'sms']];

    /**
     * Every adapter is bound over its member's default, MFA's proof store
     * (bound with a closure its proof bindings declare) included, in every
     * provider order.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testEveryAdapterIsBoundOverItsMembersDefaultInEveryProviderOrder(array $providers): void
    {
        $this->bootInOrder($providers);

        $this->assertResolvesTo(self::ADAPTERS);
        $this->assertOutcome(array_keys(self::ADAPTERS), []);
    }

    /**
     * An application binding made before any provider registers is kept over
     * every seam, in every provider order.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testAnApplicationBindingMadeBeforeAnyProviderRegistersIsKept(array $providers): void
    {
        [$bindings, $instances] = self::applicationBindings();

        $this->bootInOrder($providers, before: $bindings);

        $this->assertResolvesToInstances($instances);
        $this->assertOutcome([], array_keys(self::ADAPTERS));
    }

    /**
     * An application binding made once every provider has registered replaces
     * every adapter, in every provider order.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testAnApplicationBindingMadeOnceEveryProviderHasRegisteredWins(array $providers): void
    {
        [$bindings, $instances] = self::applicationBindings();

        $this->bootInOrder($providers, after: $bindings);

        $this->assertResolvesToInstances($instances);
        $this->assertOutcome(array_keys(self::ADAPTERS), []);
    }

    /**
     * Rows of `[delivery configuration]` under which `laravel-authentication`
     * would not deliver MFA's codes: no gateway named, only one named while the
     * shipped routes reach the other, and both named with routes that reach no
     * gateway or one this package does not know.
     *
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function provideUndeliveredFactorCodes(): iterable
    {
        yield 'no gateway named' => [['types' => ['email' => 'email', 'phone' => 'sms']]];

        yield 'only the sms gateway named' => [['sms' => self::GATEWAY, 'types' => ['email' => 'email', 'phone' => 'sms']]];

        yield 'only the email gateway named' => [['email' => self::GATEWAY, 'types' => ['email' => 'email', 'phone' => 'sms']]];

        yield 'no routes' => [['email' => self::GATEWAY, 'sms' => self::GATEWAY, 'types' => []]];

        yield 'a route to an unknown gateway' => [['email' => self::GATEWAY, 'sms' => self::GATEWAY, 'types' => ['email' => 'mail']]];
    }

    /**
     * While `laravel-authentication`'s one-time code sender would not be bound,
     * MFA keeps its own challenge gateway, sending its codes through its own
     * senders, while every other adapter is bound.
     *
     * @param  array<string, mixed>  $delivery
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideUndeliveredFactorCodes')]
    public function testMfaKeepsItsOwnChallengesWhileAuthenticationWouldNotDeliverThem(array $delivery): void
    {
        $this->delivery = $delivery;

        $this->reloadApplication();

        $adapters = array_diff_key(self::ADAPTERS, [ChallengeGateway::class => true]);

        self::assertFalse($this->app?->bound(OneTimeCodeSender::class));
        $this->assertResolvesTo([...$adapters, ChallengeGateway::class => PackageChallengeGateway::class]);
        $this->assertOutcome(array_keys($adapters), []);
    }

    /**
     * An application that binds its own MFA sender finds MFA's challenge
     * gateway bound alike whether it binds before any provider registers or
     * once every provider has registered, in every provider order, even with
     * both gateways named: which path each code takes is the adapter's to judge
     * as it sends, so the application's sender is the one its channel's codes
     * go through either way.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testAnApplicationsOwnMfaSenderBindsAlikeWheneverItIsBound(array $providers): void
    {
        foreach ([SmsSender::class, EmailSender::class] as $sender) {
            foreach ([true, false] as $before) {

                $own      = \Mockery::mock($sender);
                $bindings = [$sender => static fn (): object => $own];

                $before ? $this->bootInOrder($providers, before: $bindings) : $this->bootInOrder($providers, after: $bindings);

                $this->assertResolvesTo([ChallengeGateway::class => ChallengeGatewayAdapter::class, OneTimeCodeSender::class => OneTimeCodeSenderAdapter::class]);
                $this->assertResolvesToInstances([$sender => $own]);
            }
        }
    }

    /**
     * An application that binds its own one-time code sender before any
     * provider registers has MFA's codes delivered through it, though it names
     * no gateway, in every provider order.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testAnApplicationsOwnOneTimeCodeSenderRoutesMfasCodes(array $providers): void
    {
        $this->delivery = [];

        $own = \Mockery::mock(OneTimeCodeSender::class);

        $this->bootInOrder($providers, before: [OneTimeCodeSender::class => static fn (): object => $own]);

        $this->assertResolvesTo(self::ADAPTERS);
        self::assertSame($own, $this->app?->make(OneTimeCodeSender::class));
    }

    /**
     * The challenge gateway's binding reads, as the rule applies it, only
     * whether `laravel-authentication`'s one-time code sender would be bound:
     * by this package once the routed gateways are named, or by the
     * application. Who bound MFA's senders is never read there, but judged by
     * the adapter as each code is sent.
     *
     * @return void
     */
    public function testTheChallengeGatewaysSwitchReadsWhetherAuthenticationCanDeliver(): void
    {
        $container = new Container;
        $named     = new Repository(['iam' => ['delivery' => $this->delivery]]);
        $unnamed   = new Repository(['iam' => ['delivery' => ['types' => $this->delivery['types']]]]);
        $switch    = self::challengeGatewaySwitch(new MfaSeams(new DeliverySeams($container)), $named);

        self::assertTrue($switch($named));
        self::assertFalse($switch($unnamed));

        $container->bind(SmsSender::class, static fn (): object => \Mockery::mock(SmsSender::class));
        $container->bind(EmailSender::class, static fn (): object => \Mockery::mock(EmailSender::class));

        self::assertTrue($switch($named));
        self::assertFalse($switch($unnamed));

        $container->bind(OneTimeCodeSender::class, static fn (): object => \Mockery::mock(OneTimeCodeSender::class));

        self::assertTrue($switch($unnamed));
    }

    /**
     * With the switch off nothing is bound, and every member keeps its own
     * default.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[WithConfig(MfaSeams::SWITCH, false, defer: false)]
    public function testTheSwitchOffBindsNothing(): void
    {
        $this->assertResolvesTo(self::MEMBER_DEFAULTS);
        $this->assertOutcome([], []);
    }

    /**
     * Rows of `[value, on]`: the switch's value, and whether it leaves the
     * bindings on.
     *
     * @return iterable<string, array{0: mixed, 1: bool}>
     */
    public static function provideSwitchValues(): iterable
    {
        yield 'true' => [true, true];

        yield 'missing' => [null, true];

        yield 'empty' => ['', true];

        yield 'on' => ['on', true];

        yield 'one' => ['1', true];

        yield 'unrecognised' => ['sometimes', true];

        yield 'false' => [false, false];

        yield 'false as text' => ['false', false];

        yield 'zero' => ['0', false];

        yield 'off' => ['off', false];

        yield 'no' => ['no', false];
    }

    /**
     * The switch is read leniently: `false`, as a boolean or as text, `0`,
     * `off` and `no` turn every binding off; anything else leaves them on.
     *
     * @param  mixed  $value
     * @param  bool  $on
     * @return void
     */
    #[DataProvider('provideSwitchValues')]
    public function testTheSwitchIsReadLeniently(mixed $value, bool $on): void
    {
        $config = new Repository(['iam' => ['adapters' => ['mfa' => $value], 'delivery' => $this->delivery]]);

        foreach (self::seams()->seams($config) as $binding) {

            self::assertNotNull($binding->appliesWhen);
            self::assertSame($on, ($binding->appliesWhen)($config), $binding->abstract);
        }
    }

    /**
     * Every binding is transient over the member's own default, and only
     * revocation on factor removal and reset is mandatory (IAM-3.7).
     *
     * @return void
     */
    public function testEveryBindingIsTransientOverItsMembersDefault(): void
    {
        $bindings = self::seams()->seams(new Repository);

        self::assertSame(self::ADAPTERS, array_combine(
            array_map(static fn (SeamBinding $binding): string => $binding->abstract, $bindings),
            array_map(static fn (SeamBinding $binding): string => $binding->adapter, $bindings),
        ));

        foreach ($bindings as $binding) {

            self::assertSame(Lifetime::TRANSIENT, $binding->lifetime, $binding->abstract);
            self::assertSame($binding->abstract === SessionRevoker::class, $binding->mandatory, $binding->abstract);

            $default = $binding->abstract === ProofStore::class ? ProofBindings::class : self::MEMBER_DEFAULTS[$binding->abstract];

            self::assertSame([$default], $binding->memberDefaults, $binding->abstract);
        }
    }

    /**
     * Load the application's configuration, then the delivery configuration the
     * test holds, set as a whole, as a published configuration file holds it,
     * before any provider registers.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function resolveApplicationConfiguration(mixed $app): void
    {
        parent::resolveApplicationConfiguration($app);

        assert($app instanceof Application);

        $app->make('config')->set('iam.delivery', $this->delivery);
    }

    /**
     * The table of seams, over an empty container, so no MFA sender is the
     * application's.
     *
     * @return \SineMacula\Laravel\Iam\Mfa\MfaSeams
     */
    private static function seams(): MfaSeams
    {
        return new MfaSeams(new DeliverySeams(new Container));
    }

    /**
     * The switch of the table's challenge gateway binding.
     *
     * @param  \SineMacula\Laravel\Iam\Mfa\MfaSeams  $seams
     * @param  \Illuminate\Config\Repository  $config
     * @return \Closure(\Illuminate\Contracts\Config\Repository): bool
     */
    private static function challengeGatewaySwitch(MfaSeams $seams, Repository $config): \Closure
    {
        foreach ($seams->seams($config) as $binding) {

            if ($binding->abstract === ChallengeGateway::class && $binding->appliesWhen !== null) {
                return $binding->appliesWhen;
            }
        }

        self::fail('The table binds no challenge gateway.');
    }

    /**
     * The application's own binding of every seam, each a closure this test
     * declares returning its own instance, with those instances.
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
            self::assertInstanceOf($concrete, $this->app?->make($abstract), $abstract);
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
            self::assertSame($instance, $this->app?->make($abstract), $abstract);
        }
    }

    /**
     * Assert the binding rule bound and kept exactly the given seams among the
     * seams this table declares, in the order they are declared.
     *
     * @param  list<string>  $bound
     * @param  list<string>  $kept
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function assertOutcome(array $bound, array $kept): void
    {
        $outcome = $this->app?->make(BindingOutcome::class);
        $seams   = array_keys(self::ADAPTERS);

        self::assertInstanceOf(BindingOutcome::class, $outcome);
        self::assertSame($bound, array_values(array_intersect($outcome->bound, $seams)));
        self::assertSame($kept, array_values(array_intersect($outcome->kept, $seams)));
    }
}
