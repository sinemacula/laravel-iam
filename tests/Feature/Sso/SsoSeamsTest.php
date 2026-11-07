<?php

declare(strict_types = 1);

namespace Tests\Feature\Sso;

use Illuminate\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\ExternalEvidencePolicy;
use SineMacula\Laravel\Authentication\Contracts\ExternalIdentityLinks;
use SineMacula\Laravel\Authentication\External\InsufficientEvidence as InsufficientExternalEvidence;
use SineMacula\Laravel\Authentication\External\NoExternalLinks;
use SineMacula\Laravel\Iam\Bindings\BindingOutcome;
use SineMacula\Laravel\Iam\Bindings\BindingRule;
use SineMacula\Laravel\Iam\Bindings\Enums\Lifetime;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\IamServiceProvider;
use SineMacula\Laravel\Iam\Sso\ApplicationPolicyAdapter;
use SineMacula\Laravel\Iam\Sso\BoundLinkStorage;
use SineMacula\Laravel\Iam\Sso\ExternalEvidencePolicyAdapter;
use SineMacula\Laravel\Iam\Sso\ExternalIdentityLinksAdapter;
use SineMacula\Laravel\Iam\Sso\FreshnessAdapter;
use SineMacula\Laravel\Iam\Sso\LinkEmailMatcherAdapter;
use SineMacula\Laravel\Iam\Sso\ReauthenticationSessionsAdapter;
use SineMacula\Laravel\Iam\Sso\SessionRevocationAdapter;
use SineMacula\Laravel\Iam\Sso\SsoSeams;
use SineMacula\Laravel\Sso\Applications\ConfiguredApplicationPolicy;
use SineMacula\Laravel\Sso\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Sso\Contracts\EvidencePolicy;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Contracts\LinkEmailMatcher;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\LinkStorage;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Evidence\ConnectionEvidencePolicy;
use SineMacula\Laravel\Sso\Evidence\InsufficientEvidence;
use SineMacula\Laravel\Sso\Flows\NoReauthenticationSessions;
use SineMacula\Laravel\Sso\Freshness\RefusingFreshness;
use SineMacula\Laravel\Sso\Handoffs\DatabaseHandoffStore;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\NoEmailMatches;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\NoLinks;
use SineMacula\Laravel\Sso\Revocation\NoSessionRevocation;
use Tests\Concerns\PermutesProviderOrder;
use Tests\TestCase;

/**
 * Feature tests for the seams `laravel-authentication`, SSO and MFA join
 * through for SSO: every adapter, SSO's own link store as its linker, and its
 * link storage as whatever linker is bound, replaces its member's default in
 * every provider order; an application's own binding is kept or wins as the
 * binding rule says (IAM-8.4); SSO's handoff issuer is never touched; the link
 * store is scoped, so a long-lived worker never reaches one request's store
 * from another; SSO's per-connection evidence policy is bound, scoped, only
 * while the evidence switch is on as well, read strictly; and the capability's
 * switch turns every binding off at once.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SsoSeams::class)]
final class SsoSeamsTest extends TestCase
{
    use PermutesProviderOrder;

    /** @var array<class-string, class-string> Each seam, with the class bound over it. */
    private const array ADAPTERS = [
        ReauthenticationSessions::class => ReauthenticationSessionsAdapter::class,
        SessionRevocation::class        => SessionRevocationAdapter::class,
        ExternalIdentityLinks::class    => ExternalIdentityLinksAdapter::class,
        Linker::class                   => LinkStore::class,
        LinkStorage::class              => BoundLinkStorage::class,
        ExternalEvidencePolicy::class   => ExternalEvidencePolicyAdapter::class,
        Freshness::class                => FreshnessAdapter::class,
        ApplicationPolicy::class        => ApplicationPolicyAdapter::class,
        LinkEmailMatcher::class         => LinkEmailMatcherAdapter::class,
    ];

    /** @var array<class-string, class-string> Each seam SSO or `laravel-authentication` binds a default for, with that default. */
    private const array MEMBER_DEFAULTS = [
        ReauthenticationSessions::class => NoReauthenticationSessions::class,
        SessionRevocation::class        => NoSessionRevocation::class,
        ExternalIdentityLinks::class    => NoExternalLinks::class,
        Linker::class                   => NoLinks::class,
        ExternalEvidencePolicy::class   => InsufficientExternalEvidence::class,
        Freshness::class                => RefusingFreshness::class,
        ApplicationPolicy::class        => ConfiguredApplicationPolicy::class,
        LinkEmailMatcher::class         => NoEmailMatches::class,
        EvidencePolicy::class           => InsufficientEvidence::class,
    ];

    /** @var list<class-string> The members' own classes bound scoped over a seam. */
    private const array SCOPED = [LinkStore::class, BoundLinkStorage::class, ConnectionEvidencePolicy::class];

    /** @var array<string, mixed> The switches the application sets before any provider registers. */
    private array $switches = [];

    /**
     * Every adapter, and SSO's link store, is bound over its member's default,
     * in every provider order.
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
        $this->assertResolvesTo([EvidencePolicy::class => InsufficientEvidence::class]);
        $this->assertOutcome(array_keys(self::ADAPTERS), []);
    }

    /**
     * With the evidence switch on, SSO's evidence policy is SSO's own
     * per-connection policy, in every provider order.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testTheEvidenceSwitchBindsSsosConnectionEvidencePolicyInEveryProviderOrder(array $providers): void
    {
        $this->switches = [SsoSeams::EVIDENCE_SWITCH => true];

        $this->bootInOrder($providers);

        $this->assertResolvesTo([...self::ADAPTERS, EvidencePolicy::class => ConnectionEvidencePolicy::class]);

        $outcome = $this->app?->make(BindingOutcome::class);

        self::assertInstanceOf(BindingOutcome::class, $outcome);
        self::assertContains(EvidencePolicy::class, $outcome->bound);
    }

    /**
     * An evidence policy the application binds is kept with the evidence switch
     * on, bound before every provider registers or once they all have.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheApplicationsEvidencePolicyIsKeptWithTheSwitchOn(): void
    {
        $policy   = \Mockery::mock(EvidencePolicy::class);
        $bindings = [EvidencePolicy::class => static fn (): object => $policy];

        $this->switches = [SsoSeams::EVIDENCE_SWITCH => true];

        $this->bootInOrder([...self::MEMBER_PROVIDERS, IamServiceProvider::class], before: $bindings);

        self::assertSame($policy, $this->resolved(EvidencePolicy::class));

        $this->bootInOrder([...self::MEMBER_PROVIDERS, IamServiceProvider::class], after: $bindings);

        self::assertSame($policy, $this->resolved(EvidencePolicy::class));
    }

    /**
     * SSO's per-connection evidence policy is scoped under this package's own
     * key: the same instance within one request or job, a new one once the
     * worker resets, and the seam itself never on the container's scoped
     * instances.
     *
     * @return void
     */
    #[WithConfig(SsoSeams::EVIDENCE_SWITCH, true, defer: false)]
    public function testTheEvidencePolicyIsScopedAndForgottenWhenTheWorkerResets(): void
    {
        $app = $this->app ?? self::fail('The application has not booted.');

        $policy = $this->resolved(EvidencePolicy::class);

        self::assertInstanceOf(ConnectionEvidencePolicy::class, $policy);
        self::assertSame($policy, $this->resolved(EvidencePolicy::class));
        self::assertTrue($app->isShared(BindingRule::SCOPED_PREFIX . EvidencePolicy::class));
        self::assertFalse($app->isShared(EvidencePolicy::class));

        Iam::resetWorkerState();

        self::assertNotSame($policy, $this->resolved(EvidencePolicy::class));
    }

    /**
     * With the capability's switch off, the evidence switch binds nothing
     * either: SSO keeps its own evidence policy.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[WithConfig(SsoSeams::SWITCH, false, defer: false)]
    #[WithConfig(SsoSeams::EVIDENCE_SWITCH, true, defer: false)]
    public function testTheEvidenceSwitchBindsNothingWithTheCapabilityOff(): void
    {
        $this->assertResolvesTo([EvidencePolicy::class => InsufficientEvidence::class]);
    }

    /**
     * Rows of `[value, on]`: the evidence switch's value, and whether it binds
     * SSO's per-connection evidence policy.
     *
     * @return iterable<string, array{0: mixed, 1: bool}>
     */
    public static function provideEvidenceSwitchValues(): iterable
    {
        yield 'true' => [true, true];

        yield 'true as text' => ['true', true];

        yield 'one' => ['1', true];

        yield 'on' => ['on', true];

        yield 'yes' => ['yes', true];

        yield 'missing' => [null, false];

        yield 'empty' => ['', false];

        yield 'unrecognised' => ['sometimes', false];

        yield 'a list' => [[true], false];

        yield 'false' => [false, false];

        yield 'off' => ['off', false];
    }

    /**
     * The evidence switch is read strictly, since it widens what a provider's
     * assertion can count for: only a value that means `true` binds the
     * per-connection evidence policy, and only while the capability's switch is
     * on.
     *
     * @param  mixed  $value
     * @param  bool  $on
     * @return void
     */
    #[DataProvider('provideEvidenceSwitchValues')]
    public function testTheEvidenceSwitchIsReadStrictly(mixed $value, bool $on): void
    {
        $config = new Repository(['iam' => ['sso' => ['evidence' => $value]]]);
        $off    = new Repository(['iam' => ['adapters' => ['sso' => false], 'sso' => ['evidence' => $value]]]);

        self::assertSame($on, SsoSeams::isEvidenceOn($config));
        self::assertSame($on, self::appliesTo(EvidencePolicy::class, $config));
        self::assertFalse(self::appliesTo(EvidencePolicy::class, $off));
    }

    /**
     * SSO's handoff issuer keeps SSO's own store in every provider order, and
     * the table never names it: SSO issues and redeems its own handoff codes.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testTheHandoffIssuerKeepsSsosOwnStoreInEveryProviderOrder(array $providers): void
    {
        $this->bootInOrder($providers);

        $abstracts = array_map(static fn (SeamBinding $binding): string => $binding->abstract, (new SsoSeams)->seams(new Repository));
        $outcome   = $this->app?->make(BindingOutcome::class);

        self::assertInstanceOf(DatabaseHandoffStore::class, $this->app?->make(HandoffIssuer::class));
        self::assertNotContains(HandoffIssuer::class, $abstracts);
        self::assertInstanceOf(BindingOutcome::class, $outcome);
        self::assertNotContains(HandoffIssuer::class, [...$outcome->bound, ...$outcome->kept]);
    }

    /**
     * An application binding made before any provider registers is kept over
     * every seam, the link storage SSO binds no default for included, in every
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
     * The link store and the link storage are scoped under this package's own
     * key for each seam: the same instance within one request or job, a new one
     * once the worker resets, and the seams themselves never on the container's
     * scoped instances, so a binding the application makes over them later is
     * never forgotten.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheLinkStoreIsScopedAndForgottenWhenTheWorkerResets(): void
    {
        $app = $this->app;

        self::assertNotNull($app);

        foreach ([Linker::class, LinkStorage::class] as $seam) {

            $store = $app->make($seam);

            self::assertSame($store, $app->make($seam), $seam);
            self::assertTrue($app->isShared(BindingRule::SCOPED_PREFIX . $seam), $seam);
            self::assertFalse($app->isShared($seam), $seam);

            Iam::resetWorkerState();

            self::assertNotSame($store, $app->make($seam), $seam);
        }
    }

    /**
     * The link storage answers from the bound linker: SSO's link store with
     * this package's binding, and an application's own linker once it is bound
     * over it, never a store of its own that linker would not see.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheLinkStorageIsTheBoundLinkersOwn(): void
    {
        $app = $this->app;

        self::assertNotNull($app);

        $linker = \Mockery::mock(LinkStorage::class);

        $linker->expects('holdings')->with('connection', \Mockery::any())->andReturn(3);

        $app->instance(Linker::class, $linker);

        self::assertSame(3, $app->make(LinkStorage::class)->holdings('connection', new IdentityReference('person', '1')));
    }

    /**
     * With the switch off nothing is bound: each member keeps its own default,
     * and SSO's link storage stays unbound.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[WithConfig(SsoSeams::SWITCH, false, defer: false)]
    public function testTheSwitchOffBindsNothing(): void
    {
        $this->assertResolvesTo(self::MEMBER_DEFAULTS);
        $this->assertOutcome([], []);

        $app = $this->app;

        self::assertNotNull($app);
        self::assertFalse($app->bound(LinkStorage::class));
        self::assertInstanceOf(DatabaseHandoffStore::class, $app->make(HandoffIssuer::class));
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
        $config = new Repository(['iam' => ['adapters' => ['sso' => $value]]]);

        self::assertSame($on, SsoSeams::isOn($config));

        foreach ((new SsoSeams)->seams($config) as $binding) {

            self::assertNotNull($binding->appliesWhen);
            self::assertSame($on && $binding->abstract !== EvidencePolicy::class, ($binding->appliesWhen)($config), $binding->abstract);
        }
    }

    /**
     * Only MFA's switch is read for MFA's bindings, and only SSO's here: MFA's
     * switch off leaves SSO's bindings on.
     *
     * @return void
     */
    public function testOnlySsosSwitchIsRead(): void
    {
        $config = new Repository(['iam' => ['adapters' => ['mfa' => false]]]);

        self::assertTrue(SsoSeams::isOn($config));
    }

    /**
     * Each adapter is transient over its member's own default; SSO's link store
     * is scoped over the linker's default, the bound linker's link storage over
     * a link storage SSO binds no default for, and SSO's per-connection
     * evidence policy over its default, as SSO binds it; and only session
     * revocation is mandatory (IAM-4.4).
     *
     * @return void
     */
    public function testEachBindingsLifetimeDefaultsAndMandate(): void
    {
        $bindings = (new SsoSeams)->seams(new Repository);

        self::assertSame([...self::ADAPTERS, EvidencePolicy::class => ConnectionEvidencePolicy::class], array_combine(
            array_map(static fn (SeamBinding $binding): string => $binding->abstract, $bindings),
            array_map(static fn (SeamBinding $binding): string => $binding->adapter, $bindings),
        ));

        foreach ($bindings as $binding) {

            $store = in_array($binding->adapter, self::SCOPED, true);

            self::assertSame($store ? Lifetime::SCOPED : Lifetime::TRANSIENT, $binding->lifetime, $binding->abstract);
            self::assertSame($binding->abstract === SessionRevocation::class, $binding->mandatory, $binding->abstract);
            self::assertSame(isset(self::MEMBER_DEFAULTS[$binding->abstract]) ? [self::MEMBER_DEFAULTS[$binding->abstract]] : [], $binding->memberDefaults, $binding->abstract);
        }
    }

    /**
     * Load the application's configuration, then the switches the test sets,
     * before any provider registers, so the binding rule reads them.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function resolveApplicationConfiguration(mixed $app): void
    {
        parent::resolveApplicationConfiguration($app);

        assert($app instanceof Application);

        foreach ($this->switches as $key => $value) {
            $app->make('config')->set($key, $value);
        }
    }

    /**
     * What the container resolves the abstract to.
     *
     * @param  string  $abstract
     * @return mixed
     */
    private function resolved(string $abstract): mixed
    {
        return $this->app?->make($abstract);
    }

    /**
     * Whether the table's binding of the seam applies under the configuration.
     *
     * @param  class-string  $abstract
     * @param  \Illuminate\Config\Repository  $config
     * @return bool
     */
    private static function appliesTo(string $abstract, Repository $config): bool
    {
        foreach ((new SsoSeams)->seams($config) as $binding) {
            if ($binding->abstract === $abstract) {
                return $binding->appliesWhen !== null && ($binding->appliesWhen)($config);
            }
        }

        return self::fail(sprintf('The table declares no binding of [%s].', $abstract));
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
