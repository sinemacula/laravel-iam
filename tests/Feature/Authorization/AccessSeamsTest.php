<?php

declare(strict_types = 1);

namespace Tests\Feature\Authorization;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authentication\Applications\AdmitAnyPrincipal;
use SineMacula\Laravel\Authentication\Contracts\ApplicationAccess;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\ScopeRegistry;
use SineMacula\Laravel\Authentication\Scopes\AcceptAnyScope;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Contracts\SessionPolicySource;
use SineMacula\Laravel\Authorization\Resolvers\NoSessionPolicy;
use SineMacula\Laravel\Iam\Authorization\AccessMandates;
use SineMacula\Laravel\Iam\Authorization\ApplicationAccessAdapter;
use SineMacula\Laravel\Iam\Authorization\AuthorizationSeams;
use SineMacula\Laravel\Iam\Authorization\ScopeRegistryAdapter;
use SineMacula\Laravel\Iam\Authorization\SessionPolicySourceAdapter;
use SineMacula\Laravel\Iam\Bindings\BindingOutcome;
use SineMacula\Laravel\Iam\Bindings\BindingRule;
use SineMacula\Laravel\Iam\Bindings\Enums\Lifetime;
use SineMacula\Laravel\Iam\Checks\MandatorySeamsCheck;
use SineMacula\Laravel\Iam\Facades\Iam;
use Tests\Concerns\PermutesProviderOrder;
use Tests\Concerns\RunsChecks;
use Tests\Fixtures\Authorization\CredentialScopes;
use Tests\TestCase;

/**
 * Feature tests for the seams that cap a machine's checks by its credential's
 * scopes and hold who may use an application to its grants (IAM-6.5, IAM-6.6):
 * `laravel-authorization`'s session policy source, and
 * `laravel-authentication`'s scope registry and application access, each bound
 * over its member's default in every provider order, `laravel-authorization`'s
 * unconditional default included, and none over the application's own binding
 * or a source the application names in `laravel-authorization`'s configuration
 * (IAM-8.4). Application access is scoped, under this package's own key, so a
 * worker forgets it between units of work. The source, the registry and
 * application access are mandatory while the configuration says so, and the
 * source and the registry while the bound application policy accepts a machine
 * credential, as `iam:check` reads them, the policy asked only then; the
 * source's default is refused with the switch off and when the application
 * binds it by name, and a source the application names in
 * `laravel-authorization`'s configuration passes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationSeams::class)]
#[CoversClass(AccessMandates::class)]
#[CoversClass(MandatorySeamsCheck::class)]
final class AccessSeamsTest extends TestCase
{
    use PermutesProviderOrder, RunsChecks;

    /** @var array<class-string, class-string> Each seam, with the adapter bound over it. */
    private const array ADAPTERS = [
        SessionPolicySource::class => SessionPolicySourceAdapter::class,
        ScopeRegistry::class       => ScopeRegistryAdapter::class,
        ApplicationAccess::class   => ApplicationAccessAdapter::class,
    ];

    /** @var array<class-string, class-string> Each seam, with the class its member's own default resolves to. */
    private const array MEMBER_DEFAULTS = [
        SessionPolicySource::class => NoSessionPolicy::class,
        ScopeRegistry::class       => AcceptAnyScope::class,
        ApplicationAccess::class   => AdmitAnyPrincipal::class,
    ];

    /** @var ?class-string The session policy source the application names in `laravel-authorization`'s configuration, before any provider registers. */
    private ?string $namedSource = null;

    /** @var bool Whether the capability's switch is on, set before any provider registers. */
    private bool $switchOn = true;

    /**
     * Every adapter is bound over its member's default in every provider order,
     * `laravel-authorization`'s, which it binds unconditionally, included.
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
     * A session policy source the application names in
     * `laravel-authorization`'s configuration is kept in every provider order,
     * though `laravel-authorization` binds it with the very closure it binds
     * its default with.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testASourceTheApplicationNamesInAuthorizationsConfigurationIsKept(array $providers): void
    {
        $this->namedSource = CredentialScopes::class;

        $this->bootInOrder($providers);

        self::assertInstanceOf(CredentialScopes::class, $this->resolve(SessionPolicySource::class));
    }

    /**
     * An application binding of `laravel-authentication`'s contracts made
     * before any provider registers is kept, in every provider order.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testAnApplicationBindingOfAuthenticationsContractsMadeFirstIsKept(array $providers): void
    {
        [$bindings, $instances] = self::applicationBindings([ScopeRegistry::class, ApplicationAccess::class]);

        $this->bootInOrder($providers, before: $bindings);

        $this->assertResolvesToInstances($instances);
        $this->assertOutcome([SessionPolicySource::class], [ScopeRegistry::class, ApplicationAccess::class]);
    }

    /**
     * An application binding made once every provider has registered replaces
     * every adapter, in every provider order: `laravel-authorization`'s seam is
     * not bound again over it.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testAnApplicationBindingMadeOnceEveryProviderHasRegisteredWins(array $providers): void
    {
        [$bindings, $instances] = self::applicationBindings(array_keys(self::ADAPTERS));

        $this->bootInOrder($providers, after: $bindings);

        $this->assertResolvesToInstances($instances);
        $this->assertOutcome(array_keys(self::ADAPTERS), []);
    }

    /**
     * With the switch off nothing is bound, and every member keeps its own
     * default.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[WithConfig(AuthorizationSeams::SWITCH, false, defer: false)]
    public function testTheSwitchOffBindsNothing(): void
    {
        $this->assertResolvesTo(self::MEMBER_DEFAULTS);
        $this->assertOutcome([], []);
    }

    /**
     * The session policy source and the scope registry are transient, and
     * application access is scoped (IAM-6.6); the source is replaced only while
     * `AuthorizationServiceProvider::isPackageDefault()` says it holds
     * `laravel-authorization`'s default, and the others while
     * `AuthenticationServiceProvider::isPackageDefault()` says they hold
     * `laravel-authentication`'s.
     *
     * @return void
     */
    public function testTheSourceAndTheRegistryAreTransientAndApplicationAccessScoped(): void
    {
        $bindings = self::rows(new Repository);

        self::assertSame(Lifetime::TRANSIENT, $bindings[SessionPolicySource::class]->lifetime);
        self::assertSame(Lifetime::TRANSIENT, $bindings[ScopeRegistry::class]->lifetime);
        self::assertSame(Lifetime::SCOPED, $bindings[ApplicationAccess::class]->lifetime);

        self::assertSame([NoSessionPolicy::class], $bindings[SessionPolicySource::class]->memberDefaults);
        self::assertSame([AcceptAnyScope::class], $bindings[ScopeRegistry::class]->memberDefaults);
        self::assertSame([AdmitAnyPrincipal::class], $bindings[ApplicationAccess::class]->memberDefaults);

        $holdsDefault = new \ReflectionFunction($bindings[SessionPolicySource::class]->holdsDefault ?? self::fail('The source asks no member.'));

        self::assertSame('isPackageDefault', $holdsDefault->getName());
        self::assertSame(AuthorizationServiceProvider::class, $holdsDefault->getClosureScopeClass()?->getName());
        foreach ([ScopeRegistry::class, ApplicationAccess::class] as $contract) {
            $holdsDefault = new \ReflectionFunction($bindings[$contract]->holdsDefault ?? self::fail($contract . ' asks no member.'));

            self::assertSame(AuthenticationServiceProvider::class, $holdsDefault->getClosureScopeClass()?->getName());
        }
    }

    /**
     * Application access is held under this package's own scoped key: one
     * instance for a unit of work, forgotten by the worker reset, and the seam
     * itself never scoped, so a binding the application makes over it later is
     * never forgotten.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testApplicationAccessIsForgottenBetweenUnitsOfWork(): void
    {
        $first = $this->resolve(ApplicationAccess::class);

        self::assertInstanceOf(ApplicationAccessAdapter::class, $first);
        self::assertSame($first, $this->resolve(ApplicationAccess::class));
        self::assertTrue($this->app?->bound(BindingRule::SCOPED_PREFIX . ApplicationAccess::class) ?? false);

        Iam::resetWorkerState();

        self::assertNotSame($first, $this->resolve(ApplicationAccess::class));
    }

    /**
     * Rows of `[configuration, whether the session policy source and the scope
     * registry are mandatory, whether application access is]`.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: bool, 2: bool}>
     */
    public static function provideMandates(): iterable
    {
        yield 'no machine credential, no application mapped' => [[], false, false];

        yield 'a guard accepting API keys' => [['auth.guards.keys' => ['driver' => 'api_key', 'application' => ['methods' => ['api_key']]]], true, false];

        yield 'an application mapped' => [['authorization.application_access' => ['api' => 'api:use']], false, true];
    }

    /**
     * The session policy source and the scope registry are mandatory while a
     * guard accepts a machine credential, since `laravel-authorization`'s
     * default source caps a machine without its marker by nothing, and
     * application access while an application is mapped to the permission to
     * use it.
     *
     * @param  array<string, mixed>  $configuration
     * @param  bool  $machines
     * @param  bool  $access
     * @return void
     */
    #[DataProvider('provideMandates')]
    public function testTheAccessSeamsAreMandatoryWhileTheConfigurationSaysSo(array $configuration, bool $machines, bool $access): void
    {
        $config = new Repository;

        foreach ($configuration as $key => $value) {
            $config->set($key, $value);
        }

        $bindings = self::rows($config);

        self::assertSame($machines, $bindings[SessionPolicySource::class]->isMandatory());
        self::assertSame($machines, $bindings[ScopeRegistry::class]->isMandatory());
        self::assertSame($access, $bindings[ApplicationAccess::class]->isMandatory());
    }

    /**
     * While they are mandatory, `iam:check` passes the adapters, and refuses
     * `laravel-authentication`'s defaults bound back over them.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testIamCheckRefusesTheDefaultsWhileTheyAreMandatory(): void
    {
        $config = $this->app?->make('config');

        $config?->set('auth.guards.keys', ['driver' => 'api_key', 'provider' => 'people', 'application' => ['methods' => ['api_key']]]);
        $config?->set(AccessMandates::APPLICATION_ACCESS, ['api' => 'api:use']);

        self::assertSame([], self::problems($this->check()->checks()));

        $this->app?->singleton(ScopeRegistry::class, AcceptAnyScope::class);
        $this->app?->singleton(ApplicationAccess::class, AdmitAnyPrincipal::class);

        $problems = self::problems($this->check()->checks());

        self::assertCount(2, $problems);
        self::assertStringContainsString(ScopeRegistry::class . ' is still bound to ' . AcceptAnyScope::class, $problems[0]);
        self::assertStringContainsString(ApplicationAccess::class . ' is still bound to ' . AdmitAnyPrincipal::class, $problems[1]);
    }

    /**
     * With the switch off, while a guard accepts a machine credential,
     * `iam:check` refuses `laravel-authorization`'s default session policy
     * source, which caps an unmarked machine by nothing, though the scope
     * registry is bound off its default.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[WithConfig(AuthorizationSeams::SWITCH, false, defer: false)]
    public function testIamCheckRefusesTheDefaultSourceWithTheSwitchOff(): void
    {
        $this->acceptApiKeys();

        $this->app?->singleton(ScopeRegistry::class, ScopeRegistryAdapter::class);

        self::assertInstanceOf(NoSessionPolicy::class, $this->resolve(SessionPolicySource::class));

        $problems = self::problems($this->check()->checks());

        self::assertCount(1, $problems);
        self::assertStringContainsString(SessionPolicySource::class . ' is still bound to ' . NoSessionPolicy::class, $problems[0]);
    }

    /**
     * While a guard accepts a machine credential, `iam:check` refuses
     * `laravel-authorization`'s default session policy source the application
     * binds by its class name, though the binding rule keeps it as the
     * application's.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testIamCheckRefusesTheDefaultSourceTheApplicationBindsByName(): void
    {
        $this->acceptApiKeys();

        self::assertSame([], self::problems($this->check()->checks()));

        $this->app?->bind(SessionPolicySource::class, NoSessionPolicy::class);

        $problems = self::problems($this->check()->checks());

        self::assertCount(1, $problems);
        self::assertStringContainsString(SessionPolicySource::class . ' is still bound to ' . NoSessionPolicy::class, $problems[0]);
    }

    /**
     * Rows of `[whether the capability's switch is on]`.
     *
     * @return iterable<string, array{0: bool}>
     */
    public static function provideSwitchStates(): iterable
    {
        yield 'on' => [true];

        yield 'off' => [false];
    }

    /**
     * A session policy source the application names in
     * `laravel-authorization`'s configuration passes `iam:check` while a guard
     * accepts a machine credential, though `laravel-authorization` binds it
     * with the very closure it binds its default with, with the switch on or
     * off.
     *
     * @param  bool  $on
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideSwitchStates')]
    public function testIamCheckPassesASourceTheApplicationNamesInAuthorizationsConfiguration(bool $on): void
    {
        $this->namedSource = CredentialScopes::class;
        $this->switchOn    = $on;

        $this->refreshApplication();
        $this->acceptApiKeys();

        $this->app?->singleton(ScopeRegistry::class, ScopeRegistryAdapter::class);

        self::assertInstanceOf(CredentialScopes::class, $this->resolve(SessionPolicySource::class));
        self::assertSame([], self::problems($this->check()->checks()));
    }

    /**
     * Which machine credentials a guard accepts is the bound application
     * policy's to say: a policy of the application's that accepts a client
     * credentials exchange no guard's configuration lists makes the scope
     * registry mandatory, so `iam:check` refuses `AcceptAnyScope`; one that
     * refuses every guard's settings accepts nothing, and the registry is not.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testIamCheckAsksTheBoundApplicationPolicyWhichMachineCredentialsAGuardAccepts(): void
    {
        $accepting = self::createStub(ApplicationPolicy::class);
        $refusing  = self::createStub(ApplicationPolicy::class);

        $accepting->method('allowsMethod')->willReturnCallback(static fn (string $guard, string $method): bool => $guard === self::GUARD && $method === 'client_credentials');
        $refusing->method('allowsMethod')->willThrowException(new \InvalidArgumentException('The guard\'s settings are not set.'));

        $app = $this->app ?? self::fail('The application has not booted.');

        $app->singleton(ScopeRegistry::class, AcceptAnyScope::class);
        $app->instance(ApplicationPolicy::class, $accepting);

        self::assertFalse(AccessMandates::acceptsMachineCredentials($app->make('config')));

        $problems = self::problems($this->check()->checks());

        self::assertCount(1, $problems);
        self::assertStringContainsString(ScopeRegistry::class . ' is still bound to ' . AcceptAnyScope::class, $problems[0]);

        $app->instance(ApplicationPolicy::class, $refusing);

        self::assertSame([], self::problems($this->check()->checks()));
    }

    /**
     * The scope registry's mandate asks the application policy only when it is
     * read, as `iam:check` reads it, never when the rows are declared, as the
     * binding rule declares them while providers register and on each boot.
     *
     * @return void
     */
    public function testTheApplicationPolicyIsAskedOnlyWhenTheMandateIsRead(): void
    {
        $container = new Container;
        $asked     = new \ArrayObject;

        $container->bind(ApplicationPolicy::class, function () use ($asked): ApplicationPolicy {

            $asked->append(true);

            $policy = self::createStub(ApplicationPolicy::class);

            $policy->method('allowsMethod')->willReturn(true);

            return $policy;
        });

        $rows = [];

        foreach ((new AuthorizationSeams($container))->seams(new Repository(['auth' => ['guards' => [self::GUARD => []]]])) as $binding) {
            $rows[$binding->abstract] = $binding;
        }

        self::assertCount(0, $asked);
        self::assertTrue($rows[ScopeRegistry::class]->isMandatory());
        self::assertCount(1, $asked);
    }

    /**
     * Load the application's configuration, then turn the capability's switch
     * off where the test says so, and name the session policy source the test
     * names in `laravel-authorization`'s configuration, before any provider
     * registers, set as a whole as a published file holds it.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function resolveApplicationConfiguration(mixed $app): void
    {
        parent::resolveApplicationConfiguration($app);

        if (!$this->switchOn) {
            $app->make('config')->set(AuthorizationSeams::SWITCH, false);
        }

        if ($this->namedSource === null) {
            return;
        }

        $app->make('config')->set('authorization.session', ['source' => $this->namedSource, 'scopes' => []]);
    }

    /**
     * Have a guard accept API keys.
     *
     * @return void
     */
    private function acceptApiKeys(): void
    {
        $this->app?->make('config')->set('auth.guards.keys', ['driver' => 'api_key', 'provider' => 'people', 'application' => ['methods' => ['api_key']]]);
    }

    /**
     * Resolve the seam given from the container.
     *
     * @param  string  $abstract
     * @return mixed
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function resolve(string $abstract): mixed
    {
        return $this->app?->make($abstract);
    }

    /**
     * The check of the mandatory seams.
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
     * The table's rows over the seams under test, by seam, declared from the
     * configuration given.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return array<class-string, \SineMacula\Laravel\Iam\Bindings\SeamBinding>
     */
    private static function rows(Repository $config): array
    {
        $rows = [];

        foreach ((new AuthorizationSeams)->seams($config) as $binding) {

            if (!isset(self::ADAPTERS[$binding->abstract])) {
                continue;
            }

            self::assertSame(self::ADAPTERS[$binding->abstract], $binding->adapter);

            $rows[$binding->abstract] = $binding;
        }

        self::assertSame(array_keys(self::ADAPTERS), array_keys($rows));

        return $rows;
    }

    /**
     * The application's own binding of each seam given, each a closure this
     * test declares returning its own instance, with those instances.
     *
     * @param  list<class-string>  $seams
     * @return array{0: array<string, \Closure(): object>, 1: array<string, object>}
     */
    private static function applicationBindings(array $seams): array
    {
        $bindings  = [];
        $instances = [];

        foreach ($seams as $abstract) {

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
}
