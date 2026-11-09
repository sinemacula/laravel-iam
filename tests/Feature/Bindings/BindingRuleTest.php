<?php

declare(strict_types = 1);

namespace Tests\Feature\Bindings;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application as ApplicationContract;
use Illuminate\Foundation\Application;
use Orchestra\Testbench\Attributes\DefineEnvironment;
use Orchestra\Testbench\Attributes\WithConfig;
use Orchestra\Testbench\Foundation\Env;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Iam\Bindings\BindingOutcome;
use SineMacula\Laravel\Iam\Bindings\BindingRule;
use SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams;
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
use Tests\Fixtures\Bindings\Contracts\FeatureSeam;
use Tests\Fixtures\Bindings\Contracts\PlainSeam;
use Tests\Fixtures\Bindings\Contracts\ScopedSeam;
use Tests\Fixtures\Bindings\Contracts\SharedSeam;
use Tests\Fixtures\Bindings\Contracts\TransientSeam;
use Tests\Fixtures\Bindings\DeclaredSeams;
use Tests\Fixtures\Bindings\FixtureSeams;
use Tests\Fixtures\Bindings\FixtureSeamsProvider;
use Tests\Fixtures\Bindings\MemberDefault;
use Tests\Fixtures\Bindings\PlainBindingMemberProvider;
use Tests\Fixtures\Bindings\YieldingMemberProvider;
use Tests\TestCase;

/**
 * Feature tests for binding this package's adapters over the members' seams in
 * `register()` without ever replacing the application's binding (IAM-8.4),
 * whatever order the providers register in.
 *
 * The fixture members bind their defaults beside the real members, only where
 * nothing is bound yet, as every member does: one with `singletonIf()` of a
 * class name and `bindIf()` of a closure it declares, after
 * laravel-authentication's provider, and one with `bindIf()` and `scopedIf()`
 * of class names, after laravel-mfa's. The rule runs over the fixture seams as
 * a provider registered straight after this package's registers, as this
 * package's provider runs it over its capabilities' seams. A fixture member
 * that binds with a plain `bind()`, as laravel-authorization still binds its
 * resolvers (IAM-13.7), is added only by the tests that show what it does.
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
        MfaServiceProvider::class            => [YieldingMemberProvider::class],
        IamServiceProvider::class            => [FixtureSeamsProvider::class],
    ];

    /** @var array<class-string<\Illuminate\Support\ServiceProvider>, list<class-string<\Illuminate\Support\ServiceProvider>>> The plain-binding fixture member, registered straight after laravel-authorization's provider, as it binds. */
    private const array PLAIN_MEMBER = [
        AuthorizationServiceProvider::class => [PlainBindingMemberProvider::class],
    ];

    /** @var list<string> The key each member merges its packaged configuration under. */
    private const array MEMBER_CONFIGURATION = ['authentication', 'authorization', 'mfa', 'sso', 'audit-log'];

    /** @var list<string> The environment variables this test set, cleared once its application is destroyed. */
    private array $environment = [];

    /** @var ?array<string, mixed> The configuration the application boots with as if cached; `null` for none. */
    private ?array $cachedConfiguration = null;

    /** @var ?string The file that marks the configuration cached, removed once the application is destroyed. */
    private ?string $configurationCache = null;

    /**
     * Destroy the application, then clear the environment variables the test
     * set and remove the file that marks the configuration cached.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        parent::tearDown();

        foreach ($this->environment as $name) {
            Env::forget($name);
        }

        if ($this->configurationCache === null || !is_file($this->configurationCache)) {
            return;
        }

        unlink($this->configurationCache);
    }

    /**
     * The adapter is bound over every seam that is unbound or bound to its
     * member's default, whether the member registers before or after this
     * package, in every provider order.
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

        $this->assertResolvesTo(Adapter::class, ...FixtureSeams::SEAMS);
        $this->assertOutcome(FixtureSeams::SEAMS, []);
    }

    /**
     * An application binding made before any provider registers is kept: the
     * members leave it in place, and the rule finds it is not theirs, in every
     * provider order.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testAnApplicationBindingMadeBeforeAnyProviderRegistersIsKept(array $providers): void
    {
        $this->bootInOrder(self::withFixtures($providers), before: self::applicationBindings());

        $this->assertResolvesTo(ApplicationImplementation::class, ...FixtureSeams::SEAMS);
        $this->assertOutcome([], FixtureSeams::SEAMS);
    }

    /**
     * An application binding made once every provider has registered, as an
     * application provider's `register()` makes it, replaces the adapter the
     * rule bound, in every provider order.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testAnApplicationBindingMadeOnceEveryProviderHasRegisteredWins(array $providers): void
    {
        $this->bootInOrder(self::withFixtures($providers), after: self::applicationBindings());

        $this->assertResolvesTo(ApplicationImplementation::class, ...FixtureSeams::SEAMS);
        $this->assertOutcome(FixtureSeams::SEAMS, []);
    }

    /**
     * An application provider registered before every package provider keeps
     * its bindings in every order.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testAnApplicationProviderRegisteredBeforeThePackagesIsKept(array $providers): void
    {
        $this->bootInOrder([ApplicationRegisterProvider::class, ...self::withFixtures($providers)]);

        $this->assertResolvesTo(ApplicationImplementation::class, ...FixtureSeams::SEAMS);
        $this->assertOutcome([], FixtureSeams::SEAMS);
    }

    /**
     * An application provider registered straight before this package's keeps
     * its bindings, over the defaults of the members registered before it and
     * ahead of those registered after, in every order.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testAnApplicationProviderRegisteredStraightBeforeThisPackageIsKept(array $providers): void
    {
        $this->bootInOrder(self::withFixtures($providers, before: [IamServiceProvider::class => [ApplicationRegisterProvider::class]]));

        $this->assertResolvesTo(ApplicationImplementation::class, ...FixtureSeams::SEAMS);
        $this->assertOutcome([], FixtureSeams::SEAMS);
    }

    /**
     * An application provider registered straight after this package's replaces
     * the adapters, and the members registered after it leave its bindings in
     * place, in every order.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testAnApplicationProviderRegisteredStraightAfterThisPackageWins(array $providers): void
    {
        $this->bootInOrder(self::withFixtures($providers, after: [IamServiceProvider::class => [ApplicationRegisterProvider::class]]));

        $this->assertResolvesTo(ApplicationImplementation::class, ...FixtureSeams::SEAMS);
        $this->assertOutcome(FixtureSeams::SEAMS, []);
    }

    /**
     * An application provider registered after every package provider, where
     * Laravel registers the application's own, replaces the adapters in every
     * order.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testAnApplicationProviderRegisteredAfterThePackagesWins(array $providers): void
    {
        $this->bootInOrder([...self::withFixtures($providers), ApplicationRegisterProvider::class]);

        $this->assertResolvesTo(ApplicationImplementation::class, ...FixtureSeams::SEAMS);
        $this->assertOutcome(FixtureSeams::SEAMS, []);
    }

    /**
     * An application binding made in a `boot()` replaces the adapter, even from
     * the first provider to boot, since the rule runs as this package
     * registers.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testAnApplicationBindingMadeInBootWins(array $providers): void
    {
        $this->bootInOrder([ApplicationBootProvider::class, ...self::withFixtures($providers)]);

        $this->assertResolvesTo(ApplicationImplementation::class, ...FixtureSeams::SEAMS);
        $this->assertOutcome(FixtureSeams::SEAMS, []);
    }

    /**
     * An instance the application binds before any provider registers is kept,
     * even one of a member default's class, in every provider order.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testAnInstanceMadeBeforeAnyProviderRegistersIsKept(array $providers): void
    {
        $transient = new MemberDefault;
        $shared    = new ApplicationImplementation;

        $this->bootInOrder(self::withFixtures($providers), before: [TransientSeam::class => $transient, SharedSeam::class => $shared]);

        self::assertSame($transient, $this->application()->make(TransientSeam::class));
        self::assertSame($shared, $this->application()->make(SharedSeam::class));
        $this->assertOutcome([ScopedSeam::class, ClosureSeam::class, PlainSeam::class, FeatureSeam::class], [TransientSeam::class, SharedSeam::class]);
    }

    /**
     * An instance the application binds once every provider has registered
     * replaces the adapter, in every provider order.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testAnInstanceMadeOnceEveryProviderHasRegisteredWins(array $providers): void
    {
        $transient = new MemberDefault;
        $shared    = new ApplicationImplementation;

        $this->bootInOrder(self::withFixtures($providers), after: [TransientSeam::class => $transient, SharedSeam::class => $shared]);

        self::assertSame($transient, $this->application()->make(TransientSeam::class));
        self::assertSame($shared, $this->application()->make(SharedSeam::class));
        $this->assertOutcome(FixtureSeams::SEAMS, []);
    }

    /**
     * An application provider registered before every package provider that
     * aliases each seam to its own binding keeps the alias, in every provider
     * order.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testAnApplicationAliasMadeBeforeThePackagesIsKept(array $providers): void
    {
        $this->bootInOrder([ApplicationAliasProvider::class, ...self::withFixtures($providers)]);

        $this->assertResolvesToTheAlias();
        $this->assertOutcome([], FixtureSeams::SEAMS);
    }

    /**
     * An application provider registered after every package provider that
     * aliases each seam to its own binding wins, though the adapter stays
     * beneath the alias, in every provider order.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testAnApplicationAliasMadeAfterThePackagesWins(array $providers): void
    {
        $this->bootInOrder([...self::withFixtures($providers), ApplicationAliasProvider::class]);

        $this->assertResolvesToTheAlias();
        $this->assertOutcome(FixtureSeams::SEAMS, []);
    }

    /**
     * A seam whose switch the application's configuration turns off, set before
     * any provider registers, as Laravel loads the application's configuration
     * files, is left with the member's default and reported as neither bound
     * nor kept, in every provider order.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    #[WithConfig(FixtureSeams::SCOPED_SWITCH, false, defer: false)]
    public function testASwitchTheConfigurationTurnsOffBindsNothing(array $providers): void
    {
        $this->bootInOrder(self::withFixtures($providers));

        self::assertInstanceOf(MemberDefault::class, $this->application()->make(ScopedSeam::class));
        $this->assertOutcome([TransientSeam::class, SharedSeam::class, ClosureSeam::class, PlainSeam::class, FeatureSeam::class], []);
    }

    /**
     * The switches are read as the rule runs, in `register()`: a switch turned
     * off only once every provider has registered comes too late, and the
     * adapter stays bound.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DefineEnvironment('turnTheScopedSwitchOff')]
    public function testASwitchTurnedOffOnceEveryProviderHasRegisteredIsNotRead(): void
    {
        $this->bootInOrder(self::withFixtures([...self::MEMBER_PROVIDERS, IamServiceProvider::class]));

        self::assertFalse($this->application()->make(Repository::class)->get(FixtureSeams::SCOPED_SWITCH));
        self::assertInstanceOf(Adapter::class, $this->application()->make(ScopedSeam::class));
        $this->assertOutcome(FixtureSeams::SEAMS, []);
    }

    /**
     * A member that binds its default with a plain `bind()` before this package
     * registers is recognised as the member's default, and the adapter is bound
     * over it.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAPlainDefaultBoundBeforeThisPackageRegistersIsReplaced(): void
    {
        $this->bootInOrder(self::withFixtures([...self::MEMBER_PROVIDERS, IamServiceProvider::class], after: self::PLAIN_MEMBER));

        $this->assertResolvesTo(Adapter::class, ...FixtureSeams::SEAMS);
        $this->assertOutcome(FixtureSeams::SEAMS, []);
    }

    /**
     * A member that binds its default with a plain `bind()` after this package
     * registers replaces the adapter the rule bound, which the outcome still
     * lists as bound: that is the member's defect (IAM-13.7 for
     * laravel-authorization), which this package works around for
     * `laravel-authorization`'s seams alone, binding them again as it settles
     * (`BindingRule::reclaim()`), and not for any other member's.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAPlainDefaultBoundAfterThisPackageRegistersReplacesTheAdapter(): void
    {
        $this->bootInOrder(self::withFixtures([IamServiceProvider::class, ...self::MEMBER_PROVIDERS], after: self::PLAIN_MEMBER));

        $this->assertResolvesTo(MemberDefault::class, PlainSeam::class);
        $this->assertResolvesTo(Adapter::class, TransientSeam::class, SharedSeam::class, ScopedSeam::class, ClosureSeam::class, FeatureSeam::class);
        $this->assertOutcome(FixtureSeams::SEAMS, []);
    }

    /**
     * A member that binds its default with a plain `bind()` replaces an
     * application binding made before it, so the rule, registered after the
     * member, finds the member's default and binds the adapter over it; the
     * members that bind only what is unbound leave the application's in place.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAPlainDefaultReplacesAnApplicationBindingMadeBeforeIt(): void
    {
        $this->bootInOrder(self::withFixtures([...self::MEMBER_PROVIDERS, IamServiceProvider::class], after: self::PLAIN_MEMBER), before: self::applicationBindings());

        $this->assertResolvesTo(Adapter::class, PlainSeam::class);
        $this->assertResolvesTo(ApplicationImplementation::class, TransientSeam::class, SharedSeam::class, ScopedSeam::class, ClosureSeam::class, FeatureSeam::class);
        $this->assertOutcome([PlainSeam::class], [TransientSeam::class, SharedSeam::class, ScopedSeam::class, ClosureSeam::class, FeatureSeam::class]);
    }

    /**
     * Applied again once every provider has registered, the rule binds or keeps
     * only the seams the outcome given lists neither as bound nor as kept: it
     * binds over a seam that still holds the member's default it reserved, and
     * keeps one it never reserved, the application's; a seam switched off is
     * left with the member's default reserved there. It answers the outcome
     * with them added, and with nothing left to decide the same outcome.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function testApplyingAgainDecidesOnlyWhatTheOutcomeLeftOpen(): void
    {
        $app  = $this->application();
        $kept = new ApplicationImplementation;

        $app->instance(ScopedSeam::class, $kept);

        $capability = self::fiveSeams(static fn (): bool => false);
        $rule       = $app->make(BindingRule::class);
        $reserved   = $rule->reserve($app, new BindingOutcome([SharedSeam::class], [TransientSeam::class]), $capability);
        $outcome    = $rule->applyAgain($app, $reserved, $capability);

        self::assertSame([SharedSeam::class, PlainSeam::class], $outcome->bound);
        self::assertSame([TransientSeam::class, ScopedSeam::class], $outcome->kept);
        self::assertSame($reserved->reserved, $outcome->reserved);
        self::assertInstanceOf(Adapter::class, $app->make(PlainSeam::class));
        self::assertSame($kept, $app->make(ScopedSeam::class));
        self::assertFalse($app->bound(SharedSeam::class));
        self::assertFalse($app->bound(TransientSeam::class));
        self::assertInstanceOf(MemberDefault::class, $app->make(ClosureSeam::class));
        self::assertSame($outcome, $rule->applyAgain($app, $outcome, $capability));
    }

    /**
     * Reclaiming binds the adapter again over each seam the outcome lists as
     * bound that holds the member's own closure once more, as a member that
     * binds its defaults unconditionally leaves it when it registers after this
     * package; a seam still holding the adapter, one the application bound, its
     * member's default class by name among them, and one the rule never bound
     * are left as they are, and the outcome is not changed.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function testReclaimingBindsAgainOnlyTheSeamsAMemberBoundItsDefaultOver(): void
    {
        $app     = $this->application();
        $member  = static fn (): MemberDefault => new MemberDefault;
        $outcome = new BindingOutcome([SharedSeam::class, TransientSeam::class, PlainSeam::class, ClosureSeam::class], []);

        $app->bind(SharedSeam::class, $member);
        $app->bind(TransientSeam::class, Adapter::class);
        $app->bind(PlainSeam::class, MemberDefault::class);
        $app->bind(ScopedSeam::class, $member);
        $app->bind(ClosureSeam::class, $member);

        $capability = new readonly class implements ProvidesSeams {
            /**
             * Five seams over a member whose defaults this test declares.
             *
             * @param  \Illuminate\Contracts\Config\Repository  $config
             * @return list<\SineMacula\Laravel\Iam\Bindings\SeamBinding>
             */
            #[\Override]
            public function seams(Repository $config): array
            {
                return array_map(
                    static fn (string $seam): SeamBinding => new SeamBinding($seam, Adapter::class, [BindingRuleTest::class, MemberDefault::class]),
                    [SharedSeam::class, TransientSeam::class, PlainSeam::class, ScopedSeam::class, ClosureSeam::class],
                );
            }
        };

        $reclaimed = $app->make(BindingRule::class)->reclaim($app, $outcome, $capability);

        self::assertSame([SharedSeam::class, ClosureSeam::class], $reclaimed);
        $this->assertResolvesTo(Adapter::class, SharedSeam::class, TransientSeam::class, ClosureSeam::class);
        $this->assertResolvesTo(MemberDefault::class, PlainSeam::class, ScopedSeam::class);
        self::assertSame([SharedSeam::class, TransientSeam::class, PlainSeam::class, ClosureSeam::class], $outcome->bound);
    }

    /**
     * Applied, the rule records what binds the application's binding again for
     * each seam it kept whose member binds its defaults unconditionally (a row
     * naming its default's key), and for no other; reclaimed, it binds that
     * binding again where the member's own default holds the seam once more,
     * and leaves every other seam as it is.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function testReclaimingBindsAgainTheApplicationsBindingAMemberBoundItsDefaultOver(): void
    {
        $app = $this->application();
        $key = 'member.default:' . PlainSeam::class;

        $app->bind(PlainSeam::class, ApplicationImplementation::class);
        $app->bind(TransientSeam::class, ApplicationImplementation::class);

        $capability = new readonly class implements ProvidesSeams {
            /**
             * A seam over a member that binds its default through a key of its
             * own, and one over a member that does not.
             *
             * @param  \Illuminate\Contracts\Config\Repository  $config
             * @return list<\SineMacula\Laravel\Iam\Bindings\SeamBinding>
             */
            #[\Override]
            public function seams(Repository $config): array
            {
                return [
                    new SeamBinding(PlainSeam::class, Adapter::class, [BindingRuleTest::class, MemberDefault::class], defaultKey: 'member.default:' . PlainSeam::class),
                    new SeamBinding(TransientSeam::class, Adapter::class, [BindingRuleTest::class, MemberDefault::class]),
                ];
            }
        };

        $rule    = $app->make(BindingRule::class);
        $outcome = $rule->apply($app, $capability);

        self::assertSame([PlainSeam::class, TransientSeam::class], $outcome->kept);
        self::assertSame([PlainSeam::class], array_keys($outcome->restorers));

        $member = static fn (ApplicationContract $app): mixed => $app->make('member.default:' . PlainSeam::class);

        $app->scoped($key, MemberDefault::class);
        $app->bind(PlainSeam::class, $member);
        $app->bind(TransientSeam::class, static fn (): MemberDefault => new MemberDefault);

        self::assertSame([PlainSeam::class], $rule->reclaim($app, $outcome, $capability));
        $this->assertResolvesTo(ApplicationImplementation::class, PlainSeam::class);
        $this->assertResolvesTo(MemberDefault::class, TransientSeam::class);
        self::assertSame([], $rule->reclaim($app, $outcome, $capability));
    }

    /**
     * The rule reserves each seam the outcome left open that is unbound or
     * bound to the member's default, recording the exact binding it holds: the
     * member's default it binds there, shared, where the seam is unbound, which
     * the member's own `*If()` binding then leaves, or the member's own
     * binding. A seam bound to anything else, or with no member default to
     * bind, is not reserved, and reserving again changes nothing.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function testReservingRecordsTheMembersDefaultEachSeamHolds(): void
    {
        $app = $this->application();

        $app->singleton(SharedSeam::class, MemberDefault::class);
        $app->bind(TransientSeam::class, ApplicationImplementation::class);

        $member     = $app->getBindings()[SharedSeam::class]['concrete'];
        $capability = self::fiveSeams(static fn (): bool => true, []);
        $rule       = $app->make(BindingRule::class);
        $outcome    = $rule->reserve($app, new BindingOutcome([], []), $capability);

        self::assertSame([SharedSeam::class, PlainSeam::class, ClosureSeam::class], array_keys($outcome->reserved));
        self::assertSame($member, $outcome->reserved[SharedSeam::class]);
        self::assertSame([], $outcome->bound);
        self::assertSame([], $outcome->kept);
        self::assertFalse($app->bound(ScopedSeam::class));

        $app->singletonIf(PlainSeam::class, ApplicationImplementation::class);

        self::assertInstanceOf(MemberDefault::class, $app->make(PlainSeam::class));
        self::assertSame($app->make(PlainSeam::class), $app->make(PlainSeam::class));
        self::assertSame($outcome, $rule->reserve($app, $outcome, $capability));
    }

    /**
     * Anything bound over a reserved seam before the rule is applied again is
     * the application's and is kept, even a binding of the member's own default
     * class, which by its class alone reads as the member's; so is a reserved
     * seam whose default something has resolved and holds. A seam still holding
     * its reserved binding is bound over.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function testABindingMadeOverAReservedSeamIsKept(): void
    {
        $app        = $this->application();
        $capability = self::fiveSeams(static fn (): bool => true);
        $rule       = $app->make(BindingRule::class);
        $outcome    = $rule->reserve($app, new BindingOutcome([], []), $capability);
        $resolved   = $app->make(TransientSeam::class);

        $app->singleton(SharedSeam::class, MemberDefault::class);
        $app->bind(ClosureSeam::class, static fn (): ApplicationImplementation => new ApplicationImplementation);

        $outcome = $rule->applyAgain($app, $outcome, $capability);

        self::assertSame([ScopedSeam::class, PlainSeam::class], $outcome->bound);
        self::assertSame([SharedSeam::class, TransientSeam::class, ClosureSeam::class], $outcome->kept);
        self::assertInstanceOf(MemberDefault::class, $app->make(SharedSeam::class));
        self::assertSame($resolved, $app->make(TransientSeam::class));
        self::assertInstanceOf(ApplicationImplementation::class, $app->make(ClosureSeam::class));
        self::assertInstanceOf(Adapter::class, $app->make(ScopedSeam::class));
        self::assertInstanceOf(Adapter::class, $app->make(PlainSeam::class));
    }

    /**
     * Each adapter is bound with its declared lifetime: the transient ones are
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
        $scoped = $app->make(ScopedSeam::class);

        foreach ([TransientSeam::class, ClosureSeam::class, PlainSeam::class, FeatureSeam::class] as $transient) {
            self::assertNotSame($app->make($transient), $app->make($transient), $transient . ' is not transient.');
        }

        self::assertSame($shared, $app->make(SharedSeam::class));
        self::assertSame($scoped, $app->make(ScopedSeam::class));

        $app->forgetScopedInstances();

        self::assertSame($shared, $app->make(SharedSeam::class));
        self::assertNotSame($scoped, $app->make(ScopedSeam::class));
        self::assertInstanceOf(Adapter::class, $app->make(ScopedSeam::class));
    }

    /**
     * An instance the application binds over a scoped adapter once every
     * provider has registered outlives the scoped instances being forgotten, as
     * a queue worker forgets them before each job and Octane after each
     * request, in every provider order: the adapter is scoped under this
     * package's own key, never under the seam.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testAnInstanceMadeOverAScopedAdapterOutlivesTheScopedInstances(array $providers): void
    {
        $instance = new ApplicationImplementation;

        $this->bootInOrder(self::withFixtures($providers), after: [ScopedSeam::class => $instance]);

        $app = $this->application();

        self::assertSame($instance, $app->make(ScopedSeam::class));

        $app->forgetScopedInstances();

        self::assertSame($instance, $app->make(ScopedSeam::class));
        $this->assertOutcome(FixtureSeams::SEAMS, []);
    }

    /**
     * A singleton the application binds over a scoped adapter once the
     * application has booted stays one shared instance when the scoped
     * instances are forgotten, rather than becoming one per request or job.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testASingletonMadeOverAScopedAdapterStaysShared(): void
    {
        $this->bootInOrder(self::withFixtures([...self::MEMBER_PROVIDERS, IamServiceProvider::class]));

        $app = $this->application();

        $app->singleton(ScopedSeam::class, ApplicationImplementation::class);

        $shared = $app->make(ScopedSeam::class);

        $app->forgetScopedInstances();

        self::assertInstanceOf(ApplicationImplementation::class, $shared);
        self::assertSame($shared, $app->make(ScopedSeam::class));
    }

    /**
     * A scoped adapter is held under this package's own key for its seam, which
     * the container keeps as scoped, and the seam resolves that key's instance.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAScopedAdapterIsHeldUnderThePackagesOwnKey(): void
    {
        $this->bootInOrder(self::withFixtures([...self::MEMBER_PROVIDERS, IamServiceProvider::class]));

        $app = $this->application();

        self::assertSame($app->make(BindingRule::SCOPED_PREFIX . ScopedSeam::class), $app->make(ScopedSeam::class));
        self::assertFalse($app->isShared(ScopedSeam::class));
        self::assertTrue($app->isShared(BindingRule::SCOPED_PREFIX . ScopedSeam::class));
    }

    /**
     * A shared adapter bound over a member's `scopedIf()` default stays one
     * shared instance when the scoped instances are forgotten: the seam the
     * member scoped is taken off the container's scoped instances as the
     * adapter is bound over it.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function testASharedAdapterBoundOverAScopedDefaultStaysShared(): void
    {
        $app = $this->application();

        $app->scopedIf(SharedSeam::class, MemberDefault::class);

        $outcome = $app->make(BindingRule::class)->apply($app, new DeclaredSeams(new SeamBinding(SharedSeam::class, Adapter::class, [MemberDefault::class], Lifetime::SHARED)));
        $shared  = $app->make(SharedSeam::class);

        $app->forgetScopedInstances();

        self::assertSame([SharedSeam::class], $outcome->bound);
        self::assertInstanceOf(Adapter::class, $shared);
        self::assertSame($shared, $app->make(SharedSeam::class));
    }

    /**
     * A scoped binding keyed by its closure's return type, made before the rule
     * runs, which the container lists as the closure itself, stays scoped, and
     * the seam the rule binds over is still taken off the scoped instances.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function testAScopedBindingKeyedByItsClosureStaysScoped(): void
    {
        $app = $this->application();

        $app->scoped(static fn (): ApplicationImplementation => new ApplicationImplementation);
        $app->scopedIf(SharedSeam::class, MemberDefault::class);

        $binding       = new SeamBinding(SharedSeam::class, Adapter::class, [MemberDefault::class], Lifetime::SHARED);
        $outcome       = $app->make(BindingRule::class)->apply($app, new DeclaredSeams($binding));
        $closureScoped = $app->make(ApplicationImplementation::class);
        $shared        = $app->make(SharedSeam::class);

        $app->forgetScopedInstances();

        self::assertSame([SharedSeam::class], $outcome->bound);
        self::assertNotSame($closureScoped, $app->make(ApplicationImplementation::class));
        self::assertSame($shared, $app->make(SharedSeam::class));
    }

    /**
     * A container that is not Laravel's keeps no scoped instances to take the
     * seam off, and has the adapter bound all the same.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function testAnotherContainerHasTheAdapterBound(): void
    {
        $app = \Mockery::mock(ApplicationContract::class);

        $app->shouldReceive('make')->with(Repository::class)->andReturn(new ConfigRepository);
        $app->shouldReceive('getProviders')->andReturn([]);
        $app->shouldReceive('bound')->with(TransientSeam::class)->andReturnFalse();
        $app->shouldReceive('bind')->once()->with(TransientSeam::class, Adapter::class);

        $outcome = $this->application()->make(BindingRule::class)->apply($app, new DeclaredSeams(new SeamBinding(TransientSeam::class, Adapter::class, [MemberDefault::class])));

        self::assertSame([[TransientSeam::class], []], [$outcome->bound, $outcome->kept]);
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

        $app->register(ConditionalBindingMemberProvider::class);
        $app->register(YieldingMemberProvider::class);

        self::assertTrue($app->isBooted());

        $app->register(FixtureSeamsProvider::class);

        $this->assertResolvesTo(Adapter::class, ...FixtureSeams::SEAMS);
        $this->assertOutcome(FixtureSeams::SEAMS, []);
    }

    /**
     * The rule binds over a transient default already resolved, but keeps a
     * shared default already resolved, since whatever resolved it holds that
     * instance.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheRuleKeepsASharedDefaultResolvedBeforeItApplies(): void
    {
        $app = $this->application();

        $app->register(ConditionalBindingMemberProvider::class);
        $app->register(YieldingMemberProvider::class);

        $app->make(TransientSeam::class);

        $shared = $app->make(SharedSeam::class);

        $app->register(FixtureSeamsProvider::class);

        $this->assertResolvesTo(Adapter::class, TransientSeam::class, ScopedSeam::class, ClosureSeam::class, PlainSeam::class, FeatureSeam::class);
        self::assertSame($shared, $app->make(SharedSeam::class));
        $this->assertOutcome([TransientSeam::class, ScopedSeam::class, ClosureSeam::class, PlainSeam::class, FeatureSeam::class], [SharedSeam::class]);
    }

    /**
     * A binding whose switch, read from the configuration, is off binds nothing
     * and is reported as neither bound nor kept; one whose switch is on,
     * declared after it, is still bound.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function testABindingWhoseSwitchIsOffBindsNothing(): void
    {
        $app = $this->application();

        $app->make(Repository::class)->set(['iam-fixtures.on' => true, 'iam-fixtures.off' => false]);

        $outcome = $app->make(BindingRule::class)->apply($app, new DeclaredSeams(
            new SeamBinding(SharedSeam::class, Adapter::class, [], appliesWhen: static fn (Repository $config): bool => $config->get('iam-fixtures.off') === true),
            new SeamBinding(TransientSeam::class, Adapter::class, [], appliesWhen: static fn (Repository $config): bool => $config->get('iam-fixtures.on') === true),
        ));

        self::assertSame([TransientSeam::class], $outcome->bound);
        self::assertSame([], $outcome->kept);
        self::assertInstanceOf(Adapter::class, $app->make(TransientSeam::class));
        self::assertFalse($app->bound(SharedSeam::class));
    }

    /**
     * The outcome lists the seams bound and the seams kept, each in the order
     * the capabilities and their bindings are given, and a kept seam keeps the
     * binding it had.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function testTheOutcomeListsTheSeamsBoundAndKeptInOrder(): void
    {
        $app = $this->application();

        $app->bind(SharedSeam::class, ApplicationImplementation::class);

        $outcome = $app->make(BindingRule::class)->apply(
            $app,
            new DeclaredSeams(
                new SeamBinding(TransientSeam::class, Adapter::class, [MemberDefault::class]),
                new SeamBinding(SharedSeam::class, Adapter::class, [MemberDefault::class], Lifetime::SHARED),
            ),
            new DeclaredSeams,
            new DeclaredSeams(new SeamBinding(ScopedSeam::class, Adapter::class, [MemberDefault::class], Lifetime::SCOPED)),
        );

        self::assertSame([TransientSeam::class, ScopedSeam::class], $outcome->bound);
        self::assertSame([SharedSeam::class], $outcome->kept);
        $this->assertResolvesTo(ApplicationImplementation::class, SharedSeam::class);
    }

    /**
     * Rows of `[providers, cached]`: every provider order, with the
     * configuration loaded and merged as each provider registers, and cached.
     *
     * @return iterable<string, array{0: list<class-string<\Illuminate\Support\ServiceProvider>>, 1: bool}>
     */
    public static function provideProviderOrdersWithAndWithoutACache(): iterable
    {
        foreach (self::provideProviderOrders() as $order => [$providers]) {

            yield $order => [$providers, false];

            yield $order . ', configuration cached' => [$providers, true];
        }
    }

    /**
     * A switch on a member's feature that the member's own packaged
     * configuration turns on binds the adapter in every provider order, though
     * this package registers before the member merges that configuration in
     * some, and with the configuration cached.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @param  bool  $cached
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrdersWithAndWithoutACache')]
    public function testAMembersSwitchItsPackagedConfigurationTurnsOnBindsInEveryProviderOrder(array $providers, bool $cached): void
    {
        $this->bootInOrderCachedOrNot(self::withFixtures($providers), $cached);

        self::assertTrue($this->application()->make(Repository::class)->get(FixtureSeams::FEATURE_SWITCH));
        $this->assertResolvesTo(Adapter::class, ...FixtureSeams::SEAMS);
        $this->assertOutcome(FixtureSeams::SEAMS, []);
    }

    /**
     * A switch on a member's feature that the member's environment variable
     * turns off, through the member's own packaged configuration, binds nothing
     * in every provider order, and with the configuration cached.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @param  bool  $cached
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrdersWithAndWithoutACache')]
    public function testAMembersSwitchItsEnvironmentTurnsOffBindsNothingInEveryProviderOrder(array $providers, bool $cached): void
    {
        $this->withEnvironment(['SSO_METADATA_REFRESH' => 'false']);

        $this->bootInOrderCachedOrNot(self::withFixtures($providers), $cached);

        self::assertFalse($this->application()->make(Repository::class)->get(FixtureSeams::FEATURE_SWITCH));
        $this->assertResolvesTo(MemberDefault::class, FeatureSeam::class);
        $this->assertOutcome(array_values(array_diff(FixtureSeams::SEAMS, [FeatureSeam::class])), []);
    }

    /**
     * A member's feature switch the application's own configuration turns off,
     * set before any provider registers, wins over the member's packaged value
     * in every provider order.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    #[WithConfig('sso.features', ['metadata_refresh' => false], defer: false)]
    public function testAMembersSwitchTheApplicationsConfigurationTurnsOffBindsNothingInEveryProviderOrder(array $providers): void
    {
        $this->bootInOrder(self::withFixtures($providers));

        $this->assertResolvesTo(MemberDefault::class, FeatureSeam::class);
        $this->assertOutcome(array_values(array_diff(FixtureSeams::SEAMS, [FeatureSeam::class])), []);
    }

    /**
     * The switches read every member's configuration as the booted application
     * holds it, whether the member registered before this package or after, in
     * every provider order, and with the configuration cached.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @param  bool  $cached
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrdersWithAndWithoutACache')]
    public function testTheSwitchesReadEveryMembersConfigurationAsTheBootedApplicationHoldsIt(array $providers, bool $cached): void
    {
        $this->bootInOrderCachedOrNot(self::withFixtures($providers), $cached);

        $config   = $this->application()->make(Repository::class);
        $switches = $this->application()->make(FixtureSeamsProvider::SWITCHES);

        self::assertInstanceOf(Repository::class, $switches);

        foreach (self::MEMBER_CONFIGURATION as $key) {
            self::assertNotNull($config->get($key), $key . ' is not merged.');
            self::assertSame($config->get($key), $switches->get($key), $key . ' is read otherwise than the booted application holds it.');
        }
    }

    /**
     * A cached configuration is read as it is: Laravel merges no member's
     * packaged configuration over it, so a block the cache lacks is not filled
     * from the member's file, and the switch it held reads as unset, as the
     * member itself reads it.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testACachedConfigurationIsReadAsItIs(): void
    {
        $providers = self::withFixtures([IamServiceProvider::class, ...self::MEMBER_PROVIDERS]);

        $this->bootInOrder($providers);

        /** @var array<string, array<string, mixed>> $configuration */
        $configuration = $this->application()->make(Repository::class)->all();

        unset($configuration['sso']['features']);

        $this->bootWithCachedConfiguration($providers, $configuration);

        self::assertNull($this->application()->make(Repository::class)->get(FixtureSeams::FEATURE_SWITCH));
        $this->assertResolvesTo(MemberDefault::class, FeatureSeam::class);
        $this->assertOutcome(array_values(array_diff(FixtureSeams::SEAMS, [FeatureSeam::class])), []);
    }

    /**
     * An application that cannot cache its configuration has every member's
     * packaged configuration merged beneath its own for the switches, its own
     * values winning, and its configuration is never written.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function testAnApplicationThatCannotCacheItsConfigurationHasTheMembersPackagedConfigurationRead(): void
    {
        $config     = new ConfigRepository(['sso' => ['features' => ['metadata_refresh' => false]]]);
        $capability = new DeclaredSeams;
        $app        = \Mockery::mock(ApplicationContract::class);

        $app->shouldReceive('make')->with(Repository::class)->andReturn($config);
        $app->shouldReceive('getProviders')->andReturn([]);

        $outcome = $this->application()->make(BindingRule::class)->apply($app, $capability);

        self::assertSame([[], []], [$outcome->bound, $outcome->kept]);
        self::assertNotNull($capability->switches);
        self::assertFalse($capability->switches->get(FixtureSeams::FEATURE_SWITCH));
        self::assertArrayHasKey('connection', (array) $capability->switches->get('sso.storage'));

        foreach (self::MEMBER_CONFIGURATION as $key) {
            self::assertIsArray($capability->switches->get($key), $key . ' is not read from its packaged configuration.');
        }

        self::assertSame(['sso' => ['features' => ['metadata_refresh' => false]]], $config->all());
    }

    /**
     * Load the application's configuration, then, when the test boots it as if
     * cached, the cached configuration over it, before any provider registers.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function resolveApplicationConfiguration(mixed $app): void
    {
        parent::resolveApplicationConfiguration($app);

        if ($this->cachedConfiguration === null) {
            return;
        }

        assert($app instanceof Application);

        $app->make(Repository::class)->set($this->cachedConfiguration);
    }

    /**
     * Turn the scoped seam's switch off once every provider has registered.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    protected function turnTheScopedSwitchOff(ApplicationContract $app): void
    {
        $app->make(Repository::class)->set(FixtureSeams::SCOPED_SWITCH, false);
    }

    /**
     * Set environment variables, cleared once the test's application is
     * destroyed.
     *
     * @param  array<string, string>  $variables
     * @return void
     */
    private function withEnvironment(array $variables): void
    {
        foreach ($variables as $name => $value) {
            Env::set($name, $value);

            $this->environment[] = $name;
        }
    }

    /**
     * Boot the application with the providers in the given order, then, when
     * the configuration is to be cached, again with the configuration the first
     * application booted with, as `config:cache` caches it.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @param  bool  $cached
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function bootInOrderCachedOrNot(array $providers, bool $cached): void
    {
        $this->bootInOrder($providers);

        if (!$cached) {
            return;
        }

        /** @var array<string, mixed> $configuration */
        $configuration = $this->application()->make(Repository::class)->all();

        $this->bootWithCachedConfiguration($providers, $configuration);
    }

    /**
     * Boot the application with the providers in the given order and the given
     * configuration cached: the cache file exists, so Laravel reports the
     * configuration cached and no provider merges its packaged configuration,
     * and the application starts with the cached configuration loaded before
     * any provider registers. Testbench never reads the file, so the
     * configuration is loaded from memory.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @param  array<string, mixed>  $configuration
     * @return void
     */
    private function bootWithCachedConfiguration(array $providers, array $configuration): void
    {
        $this->configurationCache = (string) tempnam(sys_get_temp_dir(), 'iam-config-');

        file_put_contents($this->configurationCache, "<?php\n\nreturn [];\n");

        $this->withEnvironment(['APP_CONFIG_CACHE' => $this->configurationCache]);

        $this->cachedConfiguration = $configuration;

        $this->bootInOrder($providers);

        self::assertTrue($this->application()->configurationIsCached());
    }

    /**
     * A capability declaring five fixture seams, each over the member's default
     * given (`MemberDefault` unless another list is given), the last switched
     * as given.
     *
     * @param  \Closure(): bool  $closureSeamOn
     * @param  ?list<class-string>  $scopedDefaults
     * @return \SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams
     */
    private static function fiveSeams(\Closure $closureSeamOn, ?array $scopedDefaults = null): ProvidesSeams
    {
        return new readonly class ($closureSeamOn, $scopedDefaults ?? [MemberDefault::class]) implements ProvidesSeams {
            /**
             * Constructor.
             *
             * @param  \Closure(): bool  $closureSeamOn
             * @param  list<class-string>  $scopedDefaults
             */
            public function __construct(

                /** The switch of the closure seam's binding. */
                private \Closure $closureSeamOn,

                /** The scoped seam's member defaults. */
                private array $scopedDefaults,
            ) {}

            /**
             * Five seams over the member's default.
             *
             * @param  \Illuminate\Contracts\Config\Repository  $config
             * @return list<\SineMacula\Laravel\Iam\Bindings\SeamBinding>
             */
            #[\Override]
            public function seams(Repository $config): array
            {
                return [
                    new SeamBinding(SharedSeam::class, Adapter::class, [MemberDefault::class]),
                    new SeamBinding(TransientSeam::class, Adapter::class, [MemberDefault::class]),
                    new SeamBinding(ScopedSeam::class, Adapter::class, $this->scopedDefaults),
                    new SeamBinding(PlainSeam::class, Adapter::class, [MemberDefault::class]),
                    new SeamBinding(ClosureSeam::class, Adapter::class, [MemberDefault::class], appliesWhen: $this->closureSeamOn),
                ];
            }
        };
    }

    /**
     * Return the application's own binding of every fixture seam: its class
     * name, or for the closure seam a closure of its own.
     *
     * @return array<class-string, class-string|(\Closure(): \Tests\Fixtures\Bindings\ApplicationImplementation)>
     */
    private static function applicationBindings(): array
    {
        return [
            TransientSeam::class => ApplicationImplementation::class,
            SharedSeam::class    => ApplicationImplementation::class,
            ScopedSeam::class    => ApplicationImplementation::class,
            ClosureSeam::class   => static fn (): ApplicationImplementation => new ApplicationImplementation,
            PlainSeam::class     => ApplicationImplementation::class,
            FeatureSeam::class   => ApplicationImplementation::class,
        ];
    }

    /**
     * Insert the fixture providers into a provider order: each fixture member
     * straight after the real member it binds like, and the fixture rule
     * straight after this package's provider, with any other providers given
     * straight before or after the provider they are keyed by.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @param  array<class-string<\Illuminate\Support\ServiceProvider>, list<class-string<\Illuminate\Support\ServiceProvider>>>  $before
     * @param  array<class-string<\Illuminate\Support\ServiceProvider>, list<class-string<\Illuminate\Support\ServiceProvider>>>  $after
     * @return list<class-string<\Illuminate\Support\ServiceProvider>>
     */
    private static function withFixtures(array $providers, array $before = [], array $after = []): array
    {
        $ordered = [];

        foreach ($providers as $provider) {
            $ordered = [...$ordered, ...$before[$provider] ?? [], $provider, ...self::FIXTURES_AFTER[$provider] ?? [], ...$after[$provider] ?? []];
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
     * Assert that every fixture seam resolves to the application's one shared
     * implementation, through the alias.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function assertResolvesToTheAlias(): void
    {
        $implementation = $this->application()->make(ApplicationImplementation::class);

        foreach (FixtureSeams::SEAMS as $seam) {
            self::assertSame($implementation, $this->application()->make($seam), $seam . ' lost its alias.');
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
