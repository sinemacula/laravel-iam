<?php

declare(strict_types = 1);

namespace Tests\Feature\Mfa;

use Illuminate\Config\Repository;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Iam\Bindings\BindingOutcome;
use SineMacula\Laravel\Iam\Bindings\Enums\Lifetime;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Iam\Mfa\ActiveTenantResolverAdapter;
use SineMacula\Laravel\Iam\Mfa\ApplicationResolverAdapter;
use SineMacula\Laravel\Iam\Mfa\ContextSeams;
use SineMacula\Laravel\Iam\Mfa\EventContextResolverAdapter;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use SineMacula\Laravel\Iam\Mfa\SubjectTypeResolverAdapter;
use SineMacula\Laravel\Mfa\Context\DefaultEventContextResolver;
use SineMacula\Laravel\Mfa\Context\IdentityContractSubjectType;
use SineMacula\Laravel\Mfa\Contracts\ActiveTenantResolver;
use SineMacula\Laravel\Mfa\Contracts\ApplicationResolver;
use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver;
use SineMacula\Laravel\Mfa\Requirements\NoActiveTenant;
use Tests\Concerns\PermutesProviderOrder;
use Tests\TestCase;

/**
 * Feature tests for the seams MFA reads its context through (IAM-3.12): each
 * adapter replaces its member's default, MFA's unbound application resolver
 * included, in every provider order; an application's own binding is kept or
 * wins as the binding rule says (IAM-8.4); each is transient; and every binding
 * follows MFA's capability switch.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ContextSeams::class)]
final class ContextSeamsTest extends TestCase
{
    use PermutesProviderOrder;

    /** @var array<class-string, class-string> Each seam, with the adapter bound over it. */
    private const array ADAPTERS = [
        EventContextResolver::class => EventContextResolverAdapter::class,
        ActiveTenantResolver::class => ActiveTenantResolverAdapter::class,
        SubjectTypeResolver::class  => SubjectTypeResolverAdapter::class,
        ApplicationResolver::class  => ApplicationResolverAdapter::class,
    ];

    /** @var array<class-string, list<class-string>> Each seam, with its member's own defaults. */
    private const array MEMBER_DEFAULTS = [
        EventContextResolver::class => [DefaultEventContextResolver::class],
        ActiveTenantResolver::class => [NoActiveTenant::class],
        SubjectTypeResolver::class  => [IdentityContractSubjectType::class],
        ApplicationResolver::class  => [],
    ];

    /**
     * Every adapter is bound over its member's default, and over nothing where
     * MFA binds no application resolver, in every provider order.
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

        foreach (self::ADAPTERS as $abstract => $adapter) {
            self::assertInstanceOf($adapter, $this->app?->make($abstract), $abstract);
        }

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
     * With MFA's switch off nothing is bound: each member keeps its own
     * default, and the application resolver stays unbound.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[WithConfig(MfaSeams::SWITCH, false, defer: false)]
    public function testTheSwitchOffBindsNothing(): void
    {
        foreach (self::MEMBER_DEFAULTS as $abstract => $defaults) {

            if ($defaults === []) {
                self::assertFalse($this->app?->bound($abstract), $abstract);

                continue;
            }

            self::assertInstanceOf($defaults[0], $this->app?->make($abstract), $abstract);
        }

        $this->assertOutcome([], []);
    }

    /**
     * Every binding is transient over its member's default, and none is
     * mandatory.
     *
     * @return void
     */
    public function testEveryBindingIsTransientOverItsMembersDefault(): void
    {
        $bindings = (new ContextSeams)->seams(new Repository);

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
     * Rows of `[value, on]`: MFA's capability switch, and whether it leaves the
     * bindings on.
     *
     * @return iterable<string, array{0: mixed, 1: bool}>
     */
    public static function provideSwitchValues(): iterable
    {
        yield 'missing' => [null, true];

        yield 'on' => ['on', true];

        yield 'off' => ['off', false];

        yield 'false' => [false, false];
    }

    /**
     * Every binding follows MFA's capability switch, read leniently.
     *
     * @param  mixed  $value
     * @param  bool  $on
     * @return void
     */
    #[DataProvider('provideSwitchValues')]
    public function testEveryBindingFollowsTheMfaSwitch(mixed $value, bool $on): void
    {
        $config = new Repository(['iam' => ['adapters' => ['mfa' => $value]]]);

        foreach ((new ContextSeams)->seams($config) as $binding) {

            self::assertNotNull($binding->appliesWhen);
            self::assertSame($on, ($binding->appliesWhen)($config), $binding->abstract);
        }
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
     * context seams, in the order they are declared.
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
