<?php

declare(strict_types = 1);

namespace Tests\Feature\Bindings;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Iam\Bindings\BindingOutcome;
use SineMacula\Laravel\Iam\Bindings\BindingRule;
use SineMacula\Laravel\Iam\Bindings\Enums\Lifetime;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Iam\IamServiceProvider;
use SineMacula\Laravel\Mfa\MfaServiceProvider;
use Tests\Concerns\PermutesProviderOrder;
use Tests\Fixtures\Bindings\Adapter;
use Tests\Fixtures\Bindings\ApplicationAliasProvider;
use Tests\Fixtures\Bindings\ApplicationBootProvider;
use Tests\Fixtures\Bindings\ApplicationImplementation;
use Tests\Fixtures\Bindings\ApplicationRegisterProvider;
use Tests\Fixtures\Bindings\ConditionalBindingMemberProvider;
use Tests\Fixtures\Bindings\Contracts\ClosureSeam;
use Tests\Fixtures\Bindings\Contracts\PlainSeam;
use Tests\Fixtures\Bindings\Contracts\SharedSeam;
use Tests\Fixtures\Bindings\FixtureSeamsProvider;
use Tests\Fixtures\Bindings\MemberDefault;
use Tests\Fixtures\Bindings\PlainBindingMemberProvider;
use Tests\Fixtures\Bindings\RegistersFixtureSeamsWhileBooting;
use Tests\TestCase;

/**
 * Feature tests for binding this package's adapters over the members' seams
 * without ever replacing the application's binding (IAM-8.4), whatever order
 * the providers register in.
 *
 * The fixture members bind their defaults beside the real members: one with a
 * plain `bind()`, as laravel-mfa did before laravel-mfa#90 and as any provider
 * may, after its provider, and one with `singletonIf()` and a closure, as
 * laravel-authentication does, after its provider. The rule runs over the
 * fixture seams from a `booting()` callback registered beside this package's
 * provider, as this package's provider runs it over its capabilities' seams.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(BindingRule::class)]
final class BindingRuleTest extends TestCase
{
    use PermutesProviderOrder;

    /** @var array<class-string<\Illuminate\Support\ServiceProvider>, list<class-string<\Illuminate\Support\ServiceProvider>>> The fixture providers registered straight after each provider. */
    private const array FIXTURES_AFTER = [
        AuthenticationServiceProvider::class => [ConditionalBindingMemberProvider::class],
        MfaServiceProvider::class            => [PlainBindingMemberProvider::class],
        IamServiceProvider::class            => [FixtureSeamsProvider::class],
    ];

    /** @var list<class-string> Every fixture seam, in the order the fixture bindings declare them. */
    private const array SEAMS = [PlainSeam::class, SharedSeam::class, ClosureSeam::class];

    /**
     * The adapter is bound over every member default, whether the member binds
     * it with a plain `bind()` or only where nothing is bound, in every
     * provider order.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testTheAdapterIsBoundOverEveryMemberDefaultInEveryProviderOrder(array $providers): void
    {
        $this->bootInOrder(self::withFixtures($providers));

        $this->assertResolvesTo(Adapter::class, ...self::SEAMS);
        $this->assertOutcome(self::SEAMS, []);
    }

    /**
     * An application binding made once every provider has registered, as an
     * application provider's `register()` makes it, is kept in every provider
     * order.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testAnApplicationBindingMadeOnceEveryProviderHasRegisteredIsKept(array $providers): void
    {
        $this->bootInOrder(self::withFixtures($providers), [
            PlainSeam::class   => ApplicationImplementation::class,
            SharedSeam::class  => ApplicationImplementation::class,
            ClosureSeam::class => static fn (): ApplicationImplementation => new ApplicationImplementation,
        ]);

        $this->assertResolvesTo(ApplicationImplementation::class, ...self::SEAMS);
        $this->assertOutcome([], self::SEAMS);
    }

    /**
     * An application provider registered after every package provider, where
     * Laravel registers the application's own, keeps its bindings in every
     * order.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testAnApplicationProviderRegisteredAfterThePackagesIsKept(array $providers): void
    {
        $this->bootInOrder([...self::withFixtures($providers), ApplicationRegisterProvider::class]);

        $this->assertResolvesTo(ApplicationImplementation::class, ...self::SEAMS);
        $this->assertOutcome([], self::SEAMS);
    }

    /**
     * An application provider registered before every package provider, this
     * package's included, keeps its bindings where the member binds only what
     * is unbound; a member's plain `bind()` replaces it first, so that seam is
     * the member's default again and the adapter is bound over it.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testAnApplicationProviderRegisteredBeforeThePackagesIsKeptWhereTheMemberLeavesIt(array $providers): void
    {
        $this->bootInOrder([ApplicationRegisterProvider::class, ...self::withFixtures($providers)]);

        $this->assertResolvesTo(ApplicationImplementation::class, SharedSeam::class, ClosureSeam::class);
        $this->assertResolvesTo(Adapter::class, PlainSeam::class);
        $this->assertOutcome([PlainSeam::class], [SharedSeam::class, ClosureSeam::class]);
    }

    /**
     * An application binding made in a `boot()` replaces the adapter, even from
     * the first provider to boot, since the rule runs before any boots.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testAnApplicationBindingMadeInBootReplacesTheAdapter(array $providers): void
    {
        $this->bootInOrder([ApplicationBootProvider::class, ...self::withFixtures($providers)]);

        $this->assertResolvesTo(ApplicationImplementation::class, ...self::SEAMS);
        $this->assertOutcome(self::SEAMS, []);
    }

    /**
     * An instance the application binds is kept, even one of a member default's
     * class, in every provider order.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testAnInstanceIsKept(array $providers): void
    {
        $plain  = new MemberDefault;
        $shared = new ApplicationImplementation;

        $this->bootInOrder(self::withFixtures($providers), [PlainSeam::class => $plain, SharedSeam::class => $shared]);

        self::assertSame($plain, $this->application()->make(PlainSeam::class));
        self::assertSame($shared, $this->application()->make(SharedSeam::class));
        $this->assertOutcome([ClosureSeam::class], [PlainSeam::class, SharedSeam::class]);
    }

    /**
     * An application provider registered after every package provider that
     * aliases each seam to its own binding keeps the alias, though each
     * member's default stays beneath it, in every provider order.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testAnApplicationAliasIsKept(array $providers): void
    {
        $this->bootInOrder([...self::withFixtures($providers), ApplicationAliasProvider::class]);

        $implementation = $this->application()->make(ApplicationImplementation::class);

        foreach (self::SEAMS as $seam) {
            self::assertSame($implementation, $this->application()->make($seam), $seam . ' lost its alias.');
        }

        $this->assertOutcome([], self::SEAMS);
    }

    /**
     * Each adapter is bound with its declared lifetime: the transient one is
     * built on every resolution, the shared one once, and the scoped one once
     * until the scoped instances are forgotten.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEachAdapterIsBoundWithItsLifetime(): void
    {
        $this->bootInOrder(self::withFixtures([...self::MEMBER_PROVIDERS, IamServiceProvider::class]));

        $app = $this->application();

        $shared = $app->make(SharedSeam::class);
        $scoped = $app->make(ClosureSeam::class);

        self::assertNotSame($app->make(PlainSeam::class), $app->make(PlainSeam::class));
        self::assertSame($shared, $app->make(SharedSeam::class));
        self::assertSame($scoped, $app->make(ClosureSeam::class));

        $app->forgetScopedInstances();

        self::assertSame($shared, $app->make(SharedSeam::class));
        self::assertNotSame($scoped, $app->make(ClosureSeam::class));
        self::assertInstanceOf(Adapter::class, $app->make(ClosureSeam::class));
    }

    /**
     * Registered after the application has booted, the rule applies at once.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheRuleAppliesAtOnceWhenRegisteredAfterBoot(): void
    {
        $app = $this->application();

        $app->register(PlainBindingMemberProvider::class);
        $app->register(ConditionalBindingMemberProvider::class);

        self::assertTrue($app->isBooted());

        $app->register(FixtureSeamsProvider::class);

        $this->assertResolvesTo(Adapter::class, ...self::SEAMS);
        $this->assertOutcome(self::SEAMS, []);
    }

    /**
     * Registered from another provider's `boot()`, once the booting callbacks
     * have run, the rule applies from its own `boot()`, and only once.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheRuleAppliesWhenRegisteredWhileTheApplicationBoots(): void
    {
        $this->bootInOrder([...self::withFixtures(self::MEMBER_PROVIDERS), IamServiceProvider::class, RegistersFixtureSeamsWhileBooting::class]);

        $app      = $this->application();
        $outcome  = $app->make(FixtureSeamsProvider::OUTCOME);
        $provider = $app->getProvider(FixtureSeamsProvider::class);

        self::assertInstanceOf(FixtureSeamsProvider::class, $provider);
        $this->assertResolvesTo(Adapter::class, ...self::SEAMS);
        $this->assertOutcome(self::SEAMS, []);

        $provider->boot();

        self::assertSame($outcome, $app->make(FixtureSeamsProvider::OUTCOME));
    }

    /**
     * Registered after the application has booted, the rule binds over a
     * transient default already resolved, but keeps a shared default already
     * resolved, since whatever resolved it holds that instance.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheRuleKeepsASharedDefaultResolvedBeforeItApplies(): void
    {
        $app = $this->application();

        $app->register(PlainBindingMemberProvider::class);
        $app->register(ConditionalBindingMemberProvider::class);

        $app->make(PlainSeam::class);

        $shared = $app->make(SharedSeam::class);

        $app->register(FixtureSeamsProvider::class);

        $this->assertResolvesTo(Adapter::class, PlainSeam::class, ClosureSeam::class);
        self::assertSame($shared, $app->make(SharedSeam::class));
        $this->assertOutcome([PlainSeam::class, ClosureSeam::class], [SharedSeam::class]);
    }

    /**
     * A binding whose switch, read from the configuration, is off binds nothing
     * and is reported as neither bound nor kept; one whose switch is on,
     * declared after it, is still bound.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testABindingWhoseSwitchIsOffBindsNothing(): void
    {
        $app = $this->application();

        $app->make(Repository::class)->set(['iam-fixtures.on' => true, 'iam-fixtures.off' => false]);

        $outcome = $app->make(BindingRule::class)->apply(
            $app,
            new SeamBinding(SharedSeam::class, Adapter::class, [], appliesWhen: static fn (Repository $config): bool => $config->get('iam-fixtures.off') === true),
            new SeamBinding(PlainSeam::class, Adapter::class, [], appliesWhen: static fn (Repository $config): bool => $config->get('iam-fixtures.on') === true),
        );

        self::assertSame([PlainSeam::class], $outcome->bound);
        self::assertSame([], $outcome->kept);
        self::assertInstanceOf(Adapter::class, $app->make(PlainSeam::class));
        self::assertFalse($app->bound(SharedSeam::class));
    }

    /**
     * The outcome lists the seams bound and the seams kept, each in the order
     * the bindings are given, and a kept seam keeps the binding it had.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheOutcomeListsTheSeamsBoundAndKeptInOrder(): void
    {
        $app = $this->application();

        $app->bind(SharedSeam::class, ApplicationImplementation::class);

        $outcome = $app->make(BindingRule::class)->apply(
            $app,
            new SeamBinding(PlainSeam::class, Adapter::class, [MemberDefault::class]),
            new SeamBinding(SharedSeam::class, Adapter::class, [MemberDefault::class], Lifetime::SHARED),
            new SeamBinding(ClosureSeam::class, Adapter::class, [MemberDefault::class], Lifetime::SCOPED),
        );

        self::assertSame([PlainSeam::class, ClosureSeam::class], $outcome->bound);
        self::assertSame([SharedSeam::class], $outcome->kept);
        $this->assertResolvesTo(ApplicationImplementation::class, SharedSeam::class);
    }

    /**
     * Insert the fixture providers into a provider order: each fixture member
     * straight after the real member it binds like, and the fixture rule
     * straight after this package's provider.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return list<class-string<\Illuminate\Support\ServiceProvider>>
     */
    private static function withFixtures(array $providers): array
    {
        $ordered = [];

        foreach ($providers as $provider) {
            $ordered = [...$ordered, $provider, ...self::FIXTURES_AFTER[$provider] ?? []];
        }

        return $ordered;
    }

    /**
     * Return the booted application.
     *
     * @return \Illuminate\Foundation\Application
     */
    private function application(): Application
    {
        self::assertNotNull($this->app);

        return $this->app;
    }

    /**
     * Assert that each seam resolves to an instance of the given class.
     *
     * @param  class-string  $class
     * @param  class-string  ...$seams
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function assertResolvesTo(string $class, string ...$seams): void
    {
        foreach ($seams as $seam) {
            self::assertInstanceOf($class, $this->application()->make($seam), $seam . ' resolves to the wrong class.');
        }
    }

    /**
     * Assert what the fixture rule reported it bound and kept.
     *
     * @param  list<class-string>  $bound
     * @param  list<class-string>  $kept
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function assertOutcome(array $bound, array $kept): void
    {
        $outcome = $this->application()->make(FixtureSeamsProvider::OUTCOME);

        self::assertInstanceOf(BindingOutcome::class, $outcome);
        self::assertSame($bound, $outcome->bound);
        self::assertSame($kept, $outcome->kept);
    }
}
