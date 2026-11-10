<?php

declare(strict_types = 1);

namespace Tests\Feature\Authorization;

use Illuminate\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Context\GuardAuthenticationContext;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationContext;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker;
use SineMacula\Laravel\Authorization\Contracts\ContextKeyCatalogue;
use SineMacula\Laravel\Authorization\Contracts\SessionPolicySource;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Enums\ContextKeyType;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Resolvers\AuthGuardSubjectResolver;
use SineMacula\Laravel\Authorization\Resolvers\RefusingRequirementChecker;
use SineMacula\Laravel\Iam\Authorization\AuthenticationContextAdapter;
use SineMacula\Laravel\Iam\Authorization\AuthenticationContextKeys;
use SineMacula\Laravel\Iam\Authorization\AuthorizationSeams;
use SineMacula\Laravel\Iam\Authorization\RequirementCheckerAdapter;
use SineMacula\Laravel\Iam\Authorization\SessionPolicySourceAdapter;
use SineMacula\Laravel\Iam\Authorization\SubjectResolverAdapter;
use SineMacula\Laravel\Iam\Bindings\BindingOutcome;
use SineMacula\Laravel\Iam\Bindings\BindingRule;
use SineMacula\Laravel\Iam\Bindings\Enums\Lifetime;
use SineMacula\Laravel\Iam\Bindings\MemberDefaults;
use SineMacula\Laravel\Iam\Checks\MandatorySeamsCheck;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\IamServiceProvider;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use Tests\Concerns\PermutesProviderOrder;
use Tests\Concerns\RunsChecks;
use Tests\Fixtures\Authorization\NamedRequirementChecker;
use Tests\Fixtures\Authorization\NamedSubjectResolver;
use Tests\Fixtures\Providers\RegistersAuthorizationWhileBooting;
use Tests\Fixtures\Providers\ResolvesAuthorizationWhileBooting;
use Tests\TestCase;

/**
 * Feature tests for the seams `laravel-authorization` decides about its subject
 * through (IAM-6.1 to IAM-6.3): its subject resolver, its authentication
 * context and its requirement checker, each bound over
 * `laravel-authorization`'s default in every provider order, the order that
 * registers it after this package included, and one registering it from another
 * provider's `boot()` or registering it again, and none over a class the
 * application names in `laravel-authorization`'s configuration or a binding it
 * makes before this package registers or once every provider has registered
 * (IAM-8.4). The requirement checker follows the MFA capability's switch too.
 * The context's keys are declared on `laravel-authorization`'s key catalogue
 * with their types while the context bound is this package's, the application's
 * own declarations kept, and its assurance keys are untestable.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationSeams::class)]
#[CoversClass(AuthenticationContextKeys::class)]
#[CoversClass(BindingRule::class)]
#[CoversClass(MemberDefaults::class)]
#[CoversClass(MandatorySeamsCheck::class)]
#[CoversClass(IamServiceProvider::class)]
#[CoversClass(AuthenticationContextAdapter::class)]
final class AuthorizationSeamsTest extends TestCase
{
    use PermutesProviderOrder, RunsChecks;

    /** @var array<class-string, class-string> Each seam, with the adapter bound over it. */
    private const array ADAPTERS = [
        SubjectResolver::class                  => SubjectResolverAdapter::class,
        AuthenticationContext::class            => AuthenticationContextAdapter::class,
        AuthenticationRequirementChecker::class => RequirementCheckerAdapter::class,
    ];

    /** @var array<class-string, class-string> Each seam, with the class `laravel-authorization`'s own default resolves to. */
    private const array MEMBER_DEFAULTS = [
        SubjectResolver::class                  => AuthGuardSubjectResolver::class,
        AuthenticationContext::class            => GuardAuthenticationContext::class,
        AuthenticationRequirementChecker::class => RefusingRequirementChecker::class,
    ];

    /** @var list<string> The context's keys that say how strongly or how recently the session was authenticated, which no condition may test. */
    private const array ASSURANCE_KEYS = [
        'authentication.amr',
        'authentication.auth_time',
        'authentication.mfa',
        'authentication.recovery_code',
        'authentication.multifactor',
        'authentication.seconds_since_step_up',
        'mfa.accepted',
        'mfa.multifactor',
        'mfa.factor_types',
        'mfa.level',
        'mfa.phishing_resistant',
        'mfa.user_verification',
        'mfa.last_verification_age_seconds',
        'sso.provider_auth_time',
        'sso.provider_amr',
        'sso.provider_acr',
        'sso.provider_authn_context_class_ref',
    ];

    /** @var array<string, mixed> What the application sets in `laravel-authorization`'s configuration before any provider registers. */
    private array $authorization = [];

    /**
     * Every adapter is bound over `laravel-authorization`'s default in every
     * provider order, including those that register it after this package,
     * where it leaves the adapter bound.
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
     * A subject resolver and a requirement checker the application names in
     * `laravel-authorization`'s configuration stand in every provider order,
     * and `laravel-authorization` says neither is its default. Registered
     * before this package, it has bound them already, and they are kept and
     * noted as kept; registered after, it binds them over the adapters this
     * package bound to the unbound seams.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testAClassTheApplicationNamesInAuthorizationsConfigurationIsKept(array $providers): void
    {
        $this->authorization = ['subject_resolver' => NamedSubjectResolver::class, 'requirement_checker' => NamedRequirementChecker::class];

        $this->bootInOrder($providers);

        self::assertInstanceOf(NamedSubjectResolver::class, $this->resolved(SubjectResolver::class));
        self::assertInstanceOf(NamedRequirementChecker::class, $this->resolved(AuthenticationRequirementChecker::class));
        self::assertInstanceOf(AuthenticationContextAdapter::class, $this->resolved(AuthenticationContext::class));

        $app = $this->app ?? self::fail('The application has not booted.');

        self::assertFalse(AuthorizationServiceProvider::isPackageDefault($app, SubjectResolver::class));
        self::assertFalse(AuthorizationServiceProvider::isPackageDefault($app, AuthenticationRequirementChecker::class));

        $named = [SubjectResolver::class, AuthenticationRequirementChecker::class];

        if (array_search(AuthorizationServiceProvider::class, $providers, true) < array_search(IamServiceProvider::class, $providers, true)) {
            $this->assertOutcome([AuthenticationContext::class], $named);
        } else {
            $this->assertOutcome(array_keys(self::ADAPTERS), []);
        }
    }

    /**
     * An application binding made once every provider has registered replaces
     * every adapter, in every provider order, and is not bound over again as
     * the providers settle.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testAnApplicationBindingMadeOnceEveryProviderHasRegisteredWins(array $providers): void
    {
        $instances = [];
        $bindings  = [];

        foreach (array_keys(self::ADAPTERS) as $abstract) {

            $instance = \Mockery::mock($abstract);

            $instance->allows('namespaces')->andReturn(['authentication']);
            $instance->allows('assuranceKeys')->andReturn([]);

            $instances[$abstract] = $instance;
            $bindings[$abstract]  = static fn (): object => $instance;
        }

        $this->bootInOrder($providers, after: $bindings);

        foreach ($instances as $abstract => $instance) {
            self::assertSame($instance, $this->resolved($abstract), $abstract);
        }
    }

    /**
     * A `laravel-authorization` another provider registers from its `boot()`,
     * which binds its defaults only then, leaves every adapter bound, and the
     * context's keys are declared; `iam:check` finds nothing to refuse.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnAuthorizationRegisteredWhileBootingLeavesEveryAdapterBound(): void
    {
        $members = array_values(array_filter(self::MEMBER_PROVIDERS, static fn (string $provider): bool => $provider !== AuthorizationServiceProvider::class));

        $this->bootInOrder([...$members, IamServiceProvider::class, RegistersAuthorizationWhileBooting::class]);

        $this->assertResolvesTo([...self::ADAPTERS, SessionPolicySource::class => SessionPolicySourceAdapter::class]);
        $this->assertOutcome(array_keys(self::ADAPTERS), []);

        self::assertNotNull($this->catalogue()->find('mfa.level'));
        self::assertSame([], self::problems($this->check()->checks()));
    }

    /**
     * What another provider resolves from `laravel-authorization` as it boots,
     * after a `laravel-authorization` registered from a provider's `boot()`, is
     * built with the adapters: the manager holds the adapter as its subject
     * resolver, and the key catalogue has the context's keys declared on it,
     * its assurance keys untestable.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testWhatIsResolvedWhileBootingIsBuiltWithTheAdapters(): void
    {
        $members = array_values(array_filter(self::MEMBER_PROVIDERS, static fn (string $provider): bool => $provider !== AuthorizationServiceProvider::class));

        $this->bootInOrder([...$members, IamServiceProvider::class, RegistersAuthorizationWhileBooting::class, ResolvesAuthorizationWhileBooting::class]);

        $manager = $this->resolved('authorization');

        self::assertInstanceOf(AuthorizationManager::class, $manager);
        self::assertSame($manager, Authorization::getFacadeRoot());
        self::assertInstanceOf(SubjectResolverAdapter::class, (new \ReflectionProperty(AuthorizationManager::class, 'subjectResolver'))->getValue($manager));

        foreach (['authentication.tenant_id' => true, 'mfa.level' => false, 'sso.connection' => true] as $path => $isTestable) {
            self::assertSame($isTestable, $this->catalogue()->find($path)?->isTestable, $path);
        }

        self::assertSame([], self::problems($this->check()->checks()));
    }

    /**
     * An application binding made before this package registers is kept in the
     * order that registers `laravel-authorization` after this package, and
     * `laravel-authorization` registered again binds nothing over it, so the
     * note `iam:check` makes of it stays true.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnApplicationBindingMadeBeforeAuthorizationRegistersAfterThisPackageIsKept(): void
    {
        $orders = iterator_to_array(self::provideProviderOrders());

        $this->bootInOrder($orders['this package first'][0], before: [
            SubjectResolver::class                  => NamedSubjectResolver::class,
            AuthenticationRequirementChecker::class => NamedRequirementChecker::class,
        ]);

        $this->app?->register(AuthorizationServiceProvider::class, force: true);

        self::assertInstanceOf(NamedSubjectResolver::class, $this->resolved(SubjectResolver::class));
        self::assertInstanceOf(NamedRequirementChecker::class, $this->resolved(AuthenticationRequirementChecker::class));
        $this->assertOutcome([AuthenticationContext::class], [SubjectResolver::class, AuthenticationRequirementChecker::class]);
        self::assertSame([], self::problems($this->check()->checks()));
    }

    /**
     * `laravel-authorization` registered again once the application has booted
     * leaves every adapter bound, and `iam:check` finds nothing to refuse.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnAuthorizationRegisteredAgainLeavesEveryAdapterBound(): void
    {
        $this->app?->register(AuthorizationServiceProvider::class, force: true);

        $this->assertResolvesTo([...self::ADAPTERS, SessionPolicySource::class => SessionPolicySourceAdapter::class]);
        self::assertSame([], self::problems($this->check()->checks()));
    }

    /**
     * With the switch off nothing is bound, and `laravel-authorization` keeps
     * its own defaults.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[WithConfig(AuthorizationSeams::SWITCH, 'off', defer: false)]
    public function testTheSwitchOffBindsNothing(): void
    {
        $this->assertResolvesTo(self::MEMBER_DEFAULTS);
        $this->assertOutcome([], []);
    }

    /**
     * With the MFA capability's switch off, the requirement checker keeps
     * `laravel-authorization`'s default, since MFA's requirement check is what
     * judges, while the subject and the context are bound.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[WithConfig(MfaSeams::SWITCH, false, defer: false)]
    public function testTheRequirementCheckerFollowsTheMfaSwitch(): void
    {
        $this->assertResolvesTo([
            SubjectResolver::class                  => SubjectResolverAdapter::class,
            AuthenticationContext::class            => AuthenticationContextAdapter::class,
            AuthenticationRequirementChecker::class => RefusingRequirementChecker::class,
        ]);
        $this->assertOutcome([SubjectResolver::class, AuthenticationContext::class], []);
    }

    /**
     * Each row names `laravel-authorization`'s default class, asks
     * `AuthorizationServiceProvider::isPackageDefault()` whether the seam holds
     * it, and is no mandatory seam; the subject resolver is scoped, as
     * `laravel-authorization`'s own default is, and the others transient.
     *
     * @return void
     */
    public function testEachRowAsksLaravelAuthorizationForItsDefaultAndOnlyTheResolverIsScoped(): void
    {
        $rows = [];

        foreach ((new AuthorizationSeams)->seams(new Repository) as $binding) {
            $rows[$binding->abstract] = $binding;
        }

        foreach (self::ADAPTERS as $abstract => $adapter) {
            self::assertSame($adapter, $rows[$abstract]->adapter);
            self::assertSame($abstract === SubjectResolver::class ? Lifetime::SCOPED : Lifetime::TRANSIENT, $rows[$abstract]->lifetime);
            self::assertSame([self::MEMBER_DEFAULTS[$abstract]], $rows[$abstract]->memberDefaults);

            $holdsDefault = new \ReflectionFunction($rows[$abstract]->holdsDefault ?? self::fail($abstract));

            self::assertSame('isPackageDefault', $holdsDefault->getName());
            self::assertSame(AuthorizationServiceProvider::class, $holdsDefault->getClosureScopeClass()?->getName());
            self::assertFalse($rows[$abstract]->mandatory);
        }
    }

    /**
     * The subject resolver is held under this package's own scoped key: one
     * instance for a unit of work, as `laravel-authorization` keeps the tenant
     * it resolved only while the resolver bound is the one that resolved it,
     * forgotten by the worker reset, and the seam itself never scoped.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheSubjectResolverIsOneForAUnitOfWork(): void
    {
        $app   = $this->app ?? self::fail('The application has not booted.');
        $first = $this->resolved(SubjectResolver::class);

        self::assertInstanceOf(SubjectResolverAdapter::class, $first);
        self::assertSame($first, $this->resolved(SubjectResolver::class));
        self::assertTrue($app->bound(BindingRule::SCOPED_PREFIX . SubjectResolver::class));
        self::assertFalse($app->isShared(SubjectResolver::class));

        Iam::resetWorkerState();

        self::assertNotSame($first, $this->resolved(SubjectResolver::class));
    }

    /**
     * Rows of `[switch value, on]`: the switch read leniently.
     *
     * @return iterable<string, array{0: mixed, 1: bool}>
     */
    public static function provideSwitchValues(): iterable
    {
        yield 'missing' => [null, true];

        yield 'empty' => ['', true];

        yield 'true' => [true, true];

        yield 'unrecognised' => ['maybe', true];

        yield 'false' => [false, false];

        yield 'off' => ['off', false];

        yield 'no' => ['no', false];

        yield 'zero' => ['0', false];
    }

    /**
     * The switch is read leniently, as the members read one an environment
     * variable fills.
     *
     * @param  mixed  $value
     * @param  bool  $on
     * @return void
     */
    #[DataProvider('provideSwitchValues')]
    public function testTheSwitchIsReadLeniently(mixed $value, bool $on): void
    {
        self::assertSame($on, AuthorizationSeams::isOn(new Repository(['iam' => ['adapters' => ['authorization' => $value]]])));
    }

    /**
     * The context's keys are declared on the key catalogue with their types,
     * and those that say how the session was authenticated are untestable, as
     * the context's assurance keys or `laravel-authorization`'s own, so a
     * policy states a requirement instead; every other key may be tested.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheContextsKeysAreDeclared(): void
    {
        $catalogue = $this->catalogue();

        foreach (AuthenticationContextKeys::KEYS as $path => $type) {

            $key = $catalogue->find($path);

            self::assertNotNull($key, $path);
            self::assertSame($type, $key->type, $path);
            self::assertSame(!in_array($path, self::ASSURANCE_KEYS, true), $key->isTestable, $path);
        }

        self::assertTrue($catalogue->permits('authentication.tenant_id', 'eq'));
        self::assertFalse($catalogue->permits('mfa.level', 'eq'));
        self::assertFalse($catalogue->permits('authentication.mfa', 'bool'));
        self::assertTrue($catalogue->permits('mfa.has_confirmed_factor', 'bool'));
    }

    /**
     * A key the application declares in `laravel-authorization`'s configuration
     * keeps its declaration.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAKeyTheApplicationDeclaresKeepsItsDeclaration(): void
    {
        $this->authorization = ['context' => ['keys' => ['sso' => ['connection' => 'list']], 'sources' => []]];

        $this->refreshApplication();

        $key = $this->catalogue()->find('sso.connection');

        self::assertNotNull($key);
        self::assertSame(ContextKeyType::LIST, $key->type);
        self::assertNotNull($this->catalogue()->find('sso.enforcement_version'));
    }

    /**
     * No key is declared while the application binds its own authentication
     * context: one it binds declares its own.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testNoKeyIsDeclaredForAnApplicationsOwnContext(): void
    {
        $this->bootInOrder(self::providerOrder(), after: [AuthenticationContext::class => GuardAuthenticationContext::class]);

        self::assertNull($this->catalogue()->find('authentication.tenant_id'));
    }

    /**
     * A key under any of the context's namespaces any segment of which is one
     * of the context's assurance keys is untestable, however it is declared;
     * a key the context leaves testable stays so, even one sharing a prefix
     * with assurance keys (`sso.provider_session_deadline`).
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheContextsAssuranceKeysAreUntestableUnderEveryNamespace(): void
    {
        $catalogue = $this->catalogue();

        foreach (AuthenticationContextAdapter::ASSURANCE_KEYS as $name) {

            foreach (AuthenticationContextAdapter::NAMESPACES as $namespace) {

                $path = $namespace . '.declared.' . $name;

                $catalogue->declare($path, ContextKeyType::STRING);

                self::assertFalse($catalogue->find($path)?->isTestable, $path);
                self::assertFalse($catalogue->permits($path, 'eq'), $path);
            }
        }

        self::assertTrue($catalogue->permits('sso.provider_session_deadline', 'before'));
        self::assertTrue($catalogue->permits('mfa.has_confirmed_factor', 'bool'));
    }

    /**
     * Load the application's configuration, then set what the test names in
     * `laravel-authorization`'s configuration before any provider registers.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function resolveApplicationConfiguration(mixed $app): void
    {
        parent::resolveApplicationConfiguration($app);

        assert($app instanceof Application);

        foreach ($this->authorization as $key => $value) {
            $app->make('config')->set('authorization.' . $key, $value);
        }
    }

    /**
     * The order the providers register in by default.
     *
     * @return list<class-string<\Illuminate\Support\ServiceProvider>>
     */
    private static function providerOrder(): array
    {
        $orders = iterator_to_array(self::provideProviderOrders());

        return $orders['this package last'][0];
    }

    /**
     * The check of the mandatory seams, with the seams the binding rule
     * decided.
     *
     * @return \SineMacula\Laravel\Iam\Checks\MandatorySeamsCheck
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function check(): MandatorySeamsCheck
    {
        $check = $this->app?->make(MandatorySeamsCheck::class);

        assert($check instanceof MandatorySeamsCheck);

        return $check;
    }

    /**
     * `laravel-authorization`'s key catalogue.
     *
     * @return \SineMacula\Laravel\Authorization\Contracts\ContextKeyCatalogue
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function catalogue(): ContextKeyCatalogue
    {
        $catalogue = $this->app?->make(ContextKeyCatalogue::class);

        assert($catalogue instanceof ContextKeyCatalogue);

        return $catalogue;
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
            self::assertInstanceOf($concrete, $this->resolved($abstract), $abstract);
        }
    }

    /**
     * Assert the binding rule bound and kept exactly the given seams among the
     * seams under test, in the order they are declared.
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

    /**
     * Resolve the abstract from the application under test, as anything that
     * asks for it does.
     *
     * @param  string  $abstract
     * @return mixed
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function resolved(string $abstract): mixed
    {
        return $this->app?->make($abstract);
    }
}
