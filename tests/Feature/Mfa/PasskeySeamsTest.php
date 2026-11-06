<?php

declare(strict_types = 1);

namespace Tests\Feature\Mfa;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\PasskeyFactorGate;
use SineMacula\Laravel\Authentication\Passkeys\NoPasskeyFactors;
use SineMacula\Laravel\Iam\Bindings\BindingOutcome;
use SineMacula\Laravel\Iam\Bindings\Enums\Lifetime;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use SineMacula\Laravel\Iam\Mfa\PasskeyFactorGateAdapter;
use SineMacula\Laravel\Iam\Mfa\PasskeyGatewayAdapter;
use SineMacula\Laravel\Iam\Mfa\PasskeySeams;
use SineMacula\Laravel\Mfa\Contracts\PasskeyGateway;
use SineMacula\Laravel\Mfa\Passkeys\UnavailablePasskeyGateway;
use Tests\Concerns\PermutesProviderOrder;
use Tests\TestCase;

/**
 * Feature tests for the seams passkeys become MFA factors through (IAM-3.10):
 * both adapters replace their members' defaults, in every provider order; the
 * passkey gateway only while an MFA application offers the `passkey` type and
 * MFA's capability switch is on, and the passkey factor gate whenever the
 * switch is, so a passkey enrolled as a factor before the type was withdrawn
 * never leaves its factor standing; an application's own binding is kept or
 * wins as the binding rule says (IAM-8.4); and the passkey factor gate is
 * mandatory.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasskeySeams::class)]
final class PasskeySeamsTest extends TestCase
{
    use PermutesProviderOrder;

    /** @var array<class-string, class-string> Each seam, with the adapter bound over it. */
    private const array ADAPTERS = [
        PasskeyGateway::class    => PasskeyGatewayAdapter::class,
        PasskeyFactorGate::class => PasskeyFactorGateAdapter::class,
    ];

    /** @var array<class-string, class-string> Each seam, with its member's own default. */
    private const array MEMBER_DEFAULTS = [
        PasskeyGateway::class    => UnavailablePasskeyGateway::class,
        PasskeyFactorGate::class => NoPasskeyFactors::class,
    ];

    /** @var list<string> The factor types the MFA application offers in the test. */
    private array $offeredTypes = ['totp', 'passkey'];

    /**
     * Both adapters are bound over their members' defaults while passkeys are
     * offered, in every provider order.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testBothAdaptersAreBoundWhilePasskeysAreOfferedInEveryProviderOrder(array $providers): void
    {
        $this->bootInOrder($providers);

        $this->assertResolvesTo(self::ADAPTERS);
        $this->assertOutcome(array_keys(self::ADAPTERS), []);
    }

    /**
     * While no MFA application offers passkeys, MFA keeps its own passkey
     * gateway, but the passkey factor gate is still bound, in every provider
     * order: a passkey enrolled as a factor before the type was withdrawn is
     * still removed with its factor.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testOnlyTheGateIsBoundWhileNoApplicationOffersPasskeys(array $providers): void
    {
        $this->offeredTypes = ['totp'];

        $this->bootInOrder($providers);

        $this->assertResolvesTo([
            PasskeyGateway::class    => UnavailablePasskeyGateway::class,
            PasskeyFactorGate::class => PasskeyFactorGateAdapter::class,
        ]);
        $this->assertOutcome([PasskeyFactorGate::class], []);
    }

    /**
     * An application binding made before any provider registers is kept over
     * both seams, in every provider order.
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
     * both adapters, in every provider order.
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
     * Rows of `[configuration, offered, on]`: what MFA's configuration and the
     * capability's switch hold, whether the passkey gateway is on, and whether
     * the passkey factor gate is.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: bool, 2: bool}>
     */
    public static function provideSwitches(): iterable
    {
        yield 'offered by one application' => [['mfa' => ['applications' => ['api' => ['types' => ['totp', 'passkey']]]]], true, true];

        yield 'offered by another application' => [['mfa' => ['applications' => ['api' => ['types' => ['totp']], 'admin' => ['types' => ['passkey']]]]], true, true];

        yield 'offered with the switch off' => [['mfa' => ['applications' => ['api' => ['types' => ['passkey']]]], 'iam' => ['adapters' => ['mfa' => 'off']]], false, false];

        yield 'not offered with the switch off' => [['mfa' => ['applications' => ['api' => ['types' => ['totp']]]], 'iam' => ['adapters' => ['mfa' => 'off']]], false, false];

        yield 'not offered' => [['mfa' => ['applications' => ['api' => ['types' => ['totp', 'sms']]]]], false, true];

        yield 'no applications' => [['mfa' => ['applications' => []]], false, true];

        yield 'applications not a map' => [['mfa' => ['applications' => 'api']], false, true];

        yield 'settings not a map' => [['mfa' => ['applications' => ['api' => 'passkey']]], false, true];

        yield 'types not a list' => [['mfa' => ['applications' => ['api' => ['types' => 'passkey']]]], false, true];

        yield 'no types' => [['mfa' => ['applications' => ['api' => []]]], false, true];

        yield 'a type spelt otherwise' => [['mfa' => ['applications' => ['api' => ['types' => ['Passkey']]]]], false, true];
    }

    /**
     * The passkey gateway is on exactly while MFA's capability switch is and an
     * MFA application offers the `passkey` type; the passkey factor gate is on
     * exactly while the switch is, whatever is offered.
     *
     * @param  array<string, mixed>  $configuration
     * @param  bool  $offered
     * @param  bool  $on
     * @return void
     */
    #[DataProvider('provideSwitches')]
    public function testTheGatewayIsOnWhilePasskeysAreOfferedAndTheGateWhileMfaIs(array $configuration, bool $offered, bool $on): void
    {
        $config   = new Repository($configuration);
        $expected = [PasskeyGateway::class => $offered, PasskeyFactorGate::class => $on];

        self::assertSame($offered, PasskeySeams::isOffered($config) && MfaSeams::isOn($config));
        self::assertSame($on, MfaSeams::isOn($config));

        foreach ((new PasskeySeams)->seams($config) as $binding) {

            self::assertNotNull($binding->appliesWhen);
            self::assertSame($expected[$binding->abstract], ($binding->appliesWhen)($config), $binding->abstract);
        }
    }

    /**
     * Both bindings are transient over their members' defaults, and only the
     * passkey factor gate is mandatory.
     *
     * @return void
     */
    public function testBothBindingsAreTransientAndTheGateIsMandatory(): void
    {
        $bindings = (new PasskeySeams)->seams(new Repository);

        self::assertSame(self::ADAPTERS, array_combine(
            array_map(static fn (SeamBinding $binding): string => $binding->abstract, $bindings),
            array_map(static fn (SeamBinding $binding): string => $binding->adapter, $bindings),
        ));

        foreach ($bindings as $binding) {
            self::assertSame(Lifetime::TRANSIENT, $binding->lifetime, $binding->abstract);
            self::assertSame($binding->abstract === PasskeyFactorGate::class, $binding->mandatory, $binding->abstract);
            self::assertSame([self::MEMBER_DEFAULTS[$binding->abstract]], $binding->memberDefaults, $binding->abstract);
        }
    }

    /**
     * Offer the factor types the test names.
     *
     * @return list<string>
     */
    #[\Override]
    protected function mfaTypes(): array
    {
        return $this->offeredTypes;
    }

    /**
     * The application's own binding of both seams, each a closure returning its
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
     * passkey seams, in the order they are declared.
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
