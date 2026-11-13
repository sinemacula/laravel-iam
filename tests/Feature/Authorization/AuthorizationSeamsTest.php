<?php

declare(strict_types = 1);

namespace Tests\Feature\Authorization;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Foundation\Application;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Access\DenyAllPolicy;
use SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy;
use SineMacula\Laravel\Authentication\Applications\AdmitAnyPrincipal;
use SineMacula\Laravel\Authentication\Contracts\ApplicationAccess;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\ScopeRegistry;
use SineMacula\Laravel\Authentication\Scopes\AcceptAnyScope;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Cache\Resolution;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Context\GuardAuthenticationContext;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationContext;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker;
use SineMacula\Laravel\Authorization\Contracts\ContextKeyCatalogue;
use SineMacula\Laravel\Authorization\Contracts\GrantHook;
use SineMacula\Laravel\Authorization\Contracts\IdentityDirectory;
use SineMacula\Laravel\Authorization\Contracts\SessionPolicySource;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Diagnostics\Declarations;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\Lifetime as ReportedLifetime;
use SineMacula\Laravel\Authorization\Enums\ContextKeyType;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Hooks\GrantHooks;
use SineMacula\Laravel\Authorization\Resolvers\AuthGuardSubjectResolver;
use SineMacula\Laravel\Authorization\Resolvers\FlatTenantTree;
use SineMacula\Laravel\Authorization\Resolvers\GuardUserIdentityDirectory;
use SineMacula\Laravel\Authorization\Resolvers\NoSessionPolicy;
use SineMacula\Laravel\Authorization\Resolvers\RefusingRequirementChecker;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Iam\Authorization\AccessMandates;
use SineMacula\Laravel\Iam\Authorization\ApplicationAccessAdapter;
use SineMacula\Laravel\Iam\Authorization\AuditAccessPolicyAdapter;
use SineMacula\Laravel\Iam\Authorization\AuthenticationContextAdapter;
use SineMacula\Laravel\Iam\Authorization\AuthenticationContextKeys;
use SineMacula\Laravel\Iam\Authorization\AuthorizationSeams;
use SineMacula\Laravel\Iam\Authorization\GrantHookAdapter;
use SineMacula\Laravel\Iam\Authorization\IdentityDirectoryAdapter;
use SineMacula\Laravel\Iam\Authorization\RequirementCheckerAdapter;
use SineMacula\Laravel\Iam\Authorization\ScopeRegistryAdapter;
use SineMacula\Laravel\Iam\Authorization\SessionPolicySourceAdapter;
use SineMacula\Laravel\Iam\Authorization\SubjectResolverAdapter;
use SineMacula\Laravel\Iam\Bindings\Enums\Lifetime;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Iam\Checks\MandatorySeamsCheck;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\IamServiceProvider;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use SineMacula\Laravel\Iam\Sso\SsoSeams;
use Tests\Concerns\RunsChecks;
use Tests\Fixtures\Authorization\NamedRequirementChecker;
use Tests\Fixtures\Authorization\NamedSubjectResolver;
use Tests\Fixtures\Providers\RegistersAuthorizationWhileBooting;
use Tests\Fixtures\Providers\ResolvesAuthorizationWhileBooting;
use Tests\TestCase;

/**
 * Feature tests for the seams authorization joins the members through.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationSeams::class)]
#[CoversClass(AuthenticationContextKeys::class)]
#[CoversClass(AuthenticationContextAdapter::class)]
final class AuthorizationSeamsTest extends TestCase
{
    use RunsChecks;

    /** @var array<class-string, array{class-string, \SineMacula\Laravel\Iam\Bindings\Enums\Lifetime, bool}> Each seam, with its adapter, its lifetime and whether it is declared to `laravel-authorization`'s report. */
    private const array ROWS = [
        SubjectResolver::class                  => [SubjectResolverAdapter::class, Lifetime::SCOPED, true],
        AuthenticationContext::class            => [AuthenticationContextAdapter::class, Lifetime::TRANSIENT, true],
        AuthenticationRequirementChecker::class => [RequirementCheckerAdapter::class, Lifetime::TRANSIENT, true],
        SessionPolicySource::class              => [SessionPolicySourceAdapter::class, Lifetime::TRANSIENT, true],
        ScopeRegistry::class                    => [ScopeRegistryAdapter::class, Lifetime::TRANSIENT, false],
        ApplicationAccess::class                => [ApplicationAccessAdapter::class, Lifetime::SCOPED, false],
        IdentityDirectory::class                => [IdentityDirectoryAdapter::class, Lifetime::TRANSIENT, true],
        GrantHook::class                        => [GrantHookAdapter::class, Lifetime::TRANSIENT, true],
        AuditAccessPolicy::class                => [AuditAccessPolicyAdapter::class, Lifetime::SHARED, false],
    ];

    /** @var array<class-string, class-string> Each seam, with the class its member's own default resolves to. */
    private const array MEMBER_DEFAULTS = [
        SubjectResolver::class                  => AuthGuardSubjectResolver::class,
        AuthenticationContext::class            => GuardAuthenticationContext::class,
        AuthenticationRequirementChecker::class => RefusingRequirementChecker::class,
        SessionPolicySource::class              => NoSessionPolicy::class,
        ScopeRegistry::class                    => AcceptAnyScope::class,
        ApplicationAccess::class                => AdmitAnyPrincipal::class,
        IdentityDirectory::class                => GuardUserIdentityDirectory::class,
        GrantHook::class                        => GrantHooks::class,
        AuditAccessPolicy::class                => DenyAllPolicy::class,
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

    /** @var array<class-string, class-string> What the application binds once every provider has registered. */
    private array $bindings = [];

    /**
     * Every adapter is bound over its member's default.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEveryAdapterIsBoundOverItsMembersDefault(): void
    {
        $this->assertResolvesTo(self::adapters());
    }

    /**
     * Each declared adapter is reported with its class, lifetime and binding.
     *
     * @return void
     */
    public function testTheDeclaredAdaptersAreReportedWithTheirBinding(): void
    {
        $app          = $this->application();
        $declarations = Declarations::of($app);
        $declared     = array_keys(array_filter(self::ROWS, static fn (array $row): bool => $row[2]));

        self::assertSame($declared, array_keys($declarations->all()));

        foreach ($declared as $contract) {

            $declaration = $declarations->for($contract) ?? self::fail($contract);

            self::assertSame(AuthorizationSeams::OWNER, $declaration->owner, $contract);
            self::assertSame([self::ROWS[$contract][0]], $declaration->classes, $contract);
            self::assertSame(self::ROWS[$contract][1] === Lifetime::SCOPED ? ReportedLifetime::SCOPED : ReportedLifetime::TRANSIENT, $declaration->lifetime, $contract);
            self::assertSame($app->getBindings()[$contract]['concrete'], $declaration->binding, $contract);
        }
    }

    /**
     * Each row names its adapter, its lifetime and whether it is declared.
     *
     * @return void
     */
    public function testEachRowsAdapterLifetimeAndDeclaration(): void
    {
        $rows = self::rows(new Repository);

        self::assertSame(array_keys(self::ROWS), array_keys($rows));

        foreach (self::ROWS as $abstract => [$adapter, $lifetime, $declared]) {
            self::assertSame($adapter, $rows[$abstract]->adapter, $abstract);
            self::assertSame($lifetime, $rows[$abstract]->lifetime, $abstract);
            self::assertSame($declared, $rows[$abstract]->declare !== null, $abstract);
        }
    }

    /**
     * Rows of `[authorization, mfa, sso, on]`.
     *
     * @return iterable<string, array{0: bool, 1: bool, 2: bool, 3: array{bool, bool, bool}}>
     */
    public static function provideSwitches(): iterable
    {
        yield 'all on' => [true, true, true, [true, true, true]];

        yield 'authorization off' => [false, true, true, [false, false, false]];

        yield 'mfa off' => [true, false, true, [true, false, true]];

        yield 'sso off' => [true, true, false, [true, true, false]];
    }

    /**
     * Every row follows the switches it depends on.
     *
     * @param  bool  $authorization
     * @param  bool  $mfa
     * @param  bool  $sso
     * @param  array{bool, bool, bool}  $on
     * @return void
     */
    #[DataProvider('provideSwitches')]
    public function testEachRowFollowsItsSwitches(bool $authorization, bool $mfa, bool $sso, array $on): void
    {
        $config = new Repository;

        $config->set(AuthorizationSeams::SWITCH, $authorization);
        $config->set(MfaSeams::SWITCH, $mfa);
        $config->set(SsoSeams::SWITCH, $sso);

        foreach (self::rows($config) as $abstract => $row) {

            $expected = match ($abstract) {
                AuthenticationRequirementChecker::class => $on[1],
                GrantHook::class                        => $on[2],
                default                                 => $on[0],
            };

            self::assertSame($expected, $row->on, $abstract);
        }

        self::assertSame($on[2], AuthorizationSeams::reportsWidenings($config));
    }

    /**
     * Rows of `[configuration, machines, access, domains]`.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: bool, 2: bool, 3: bool}>
     */
    public static function provideMandates(): iterable
    {
        yield 'nothing' => [[], false, false, false];

        yield 'a guard accepting API keys' => [['auth.guards.keys' => ['driver' => 'api_key', 'application' => ['methods' => ['api_key']]]], true, false, false];

        yield 'an application mapped' => [[AccessMandates::APPLICATION_ACCESS => ['api' => 'api:use']], false, true, false];

        yield 'domain linking' => [[AuthorizationSeams::DOMAIN_LINKING => true], false, false, true];
    }

    /**
     * Each mandate follows the configuration.
     *
     * @param  array<string, mixed>  $configuration
     * @param  bool  $machines
     * @param  bool  $access
     * @param  bool  $domains
     * @return void
     */
    #[DataProvider('provideMandates')]
    public function testTheMandatesFollowTheConfiguration(array $configuration, bool $machines, bool $access, bool $domains): void
    {
        $config = new Repository;

        foreach ($configuration as $key => $value) {
            $config->set($key, $value);
        }

        foreach (self::rows($config) as $abstract => $row) {

            $expected = match ($abstract) {
                SessionPolicySource::class, ScopeRegistry::class => $machines,
                ApplicationAccess::class                         => $access,
                GrantHook::class                                 => $domains,
                default                                          => false,
            };

            self::assertSame($expected, $row->isMandatory(), $abstract);
        }
    }

    /**
     * The machine mandate asks the bound application policy only when read.
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
     * With the switch off nothing is declared.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[WithConfig(AuthorizationSeams::SWITCH, 'off', defer: false)]
    public function testTheSwitchOffBindsNothing(): void
    {
        $this->assertResolvesTo(self::MEMBER_DEFAULTS);

        self::assertSame([], Declarations::of($this->application())->all());
    }

    /**
     * With MFA's switch off the requirement checker keeps its default.
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
            AuthenticationRequirementChecker::class => RefusingRequirementChecker::class,
        ]);
    }

    /**
     * Rows of `[switch value, on]`.
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
     * The switch is read leniently.
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
     * Classes named in `laravel-authorization`'s configuration are kept.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testClassesNamedInAuthorizationsConfigurationAreKept(): void
    {
        $this->authorization = ['subject_resolver' => NamedSubjectResolver::class, 'requirement_checker' => NamedRequirementChecker::class];

        $this->refreshApplication();

        $this->assertResolvesTo([
            SubjectResolver::class                  => NamedSubjectResolver::class,
            AuthenticationRequirementChecker::class => NamedRequirementChecker::class,
            AuthenticationContext::class            => AuthenticationContextAdapter::class,
        ]);
    }

    /**
     * Rebinding the resolver or the tree forgets cached resolutions.
     *
     * @return void
     */
    public function testRebindingTheResolverOrTheTreeForgetsResolutions(): void
    {
        $app = $this->application();

        $app->make(SubjectResolver::class);
        $app->make(TenantTree::class);

        $cache    = ResolutionCache::instance();
        $resolved = 0;
        $resolve  = static function () use (&$resolved): Resolution {
            $resolved++;

            return new Resolution(['billing']);
        };

        self::assertInstanceOf(ResolutionCache::class, $cache);

        $cache->rememberRoles(new Reference('person', '1'), $resolve);
        $cache->rememberRoles(new Reference('person', '1'), $resolve);
        $app->instance(TenantTree::class, new FlatTenantTree);
        $cache->rememberRoles(new Reference('person', '1'), $resolve);
        $app->instance(SubjectResolver::class, $app->make(AuthGuardSubjectResolver::class));
        $cache->rememberRoles(new Reference('person', '1'), $resolve);

        self::assertSame(3, $resolved);
    }

    /**
     * An authorization registered during boot still gets every adapter.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnAuthorizationRegisteredWhileBootingGetsEveryAdapter(): void
    {
        $this->reorderProviders([...self::membersButAuthorization(), IamServiceProvider::class, RegistersAuthorizationWhileBooting::class]);

        $this->assertResolvesTo(self::adapters());

        self::assertNotNull($this->catalogue()->find('mfa.level'));
        self::assertSame([], self::problems($this->check()->checks()));
    }

    /**
     * What a provider resolves while booting is built with the adapters.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testWhatIsResolvedWhileBootingIsBuiltWithTheAdapters(): void
    {
        $this->reorderProviders([
            ...self::membersButAuthorization(),
            IamServiceProvider::class,
            RegistersAuthorizationWhileBooting::class,
            ResolvesAuthorizationWhileBooting::class,
        ]);

        $manager = $this->application()->make('authorization');

        self::assertInstanceOf(AuthorizationManager::class, $manager);
        self::assertSame($manager, Authorization::getFacadeRoot());
        self::assertInstanceOf(SubjectResolverAdapter::class, (new \ReflectionProperty(AuthorizationManager::class, 'subjectResolver'))->getValue($manager));

        foreach (['authentication.tenant_id' => true, 'mfa.level' => false, 'sso.connection' => true] as $path => $isTestable) {
            self::assertSame($isTestable, $this->catalogue()->find($path)?->isTestable, $path);
        }
    }

    /**
     * `laravel-authorization` registered again leaves every adapter bound.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnAuthorizationRegisteredAgainLeavesEveryAdapterBound(): void
    {
        $this->application()->register(AuthorizationServiceProvider::class, force: true);

        $this->assertResolvesTo(self::adapters());

        self::assertSame([], self::problems($this->check()->checks()));
    }

    /**
     * The subject resolver is scoped and forgotten by the worker reset.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheSubjectResolverIsOneForAUnitOfWork(): void
    {
        $app   = $this->application();
        $first = $this->resolved(SubjectResolver::class);

        self::assertInstanceOf(SubjectResolverAdapter::class, $first);
        self::assertSame($first, $this->resolved(SubjectResolver::class));
        self::assertTrue($app->bound(SeamBinding::SCOPED_PREFIX . SubjectResolver::class));
        self::assertFalse($app->isShared(SubjectResolver::class));

        Iam::resetWorkerState();

        self::assertNotSame($first, $this->resolved(SubjectResolver::class));
    }

    /**
     * The context's keys are declared with their types.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheContextsKeysAreDeclared(): void
    {
        $catalogue = $this->catalogue();

        foreach (AuthenticationContextKeys::keys() as $path => $type) {

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
     * A key the application declares keeps its declaration.
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
     * No key is declared for an application's own authentication context.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testNoKeyIsDeclaredForAnApplicationsOwnContext(): void
    {
        $this->bindings = [AuthenticationContext::class => GuardAuthenticationContext::class];

        $this->refreshApplication();

        self::assertNull($this->catalogue()->find('authentication.tenant_id'));
    }

    /**
     * The context's assurance keys are untestable under every namespace.
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
     * Load the configuration with the test's authorization settings.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function resolveApplicationConfiguration(mixed $app): void
    {
        parent::resolveApplicationConfiguration($app);

        foreach ($this->authorization as $key => $value) {
            $app->make('config')->set('authorization.' . $key, $value);
        }
    }

    /**
     * Seed the environment, then make the application's bindings.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        foreach ($this->bindings as $abstract => $concrete) {
            $app->bind($abstract, $concrete);
        }
    }

    /**
     * Each seam, with its adapter.
     *
     * @return array<class-string, class-string>
     */
    private static function adapters(): array
    {
        return array_map(static fn (array $row): string => $row[0], self::ROWS);
    }

    /**
     * Every member's provider but `laravel-authorization`'s.
     *
     * @return list<class-string<\Illuminate\Support\ServiceProvider>>
     */
    private static function membersButAuthorization(): array
    {
        return array_values(array_filter(self::MEMBER_PROVIDERS, static fn (string $provider): bool => $provider !== AuthorizationServiceProvider::class));
    }

    /**
     * The table's rows, by seam.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return array<class-string, \SineMacula\Laravel\Iam\Bindings\SeamBinding>
     */
    private static function rows(Repository $config): array
    {
        $rows = [];

        foreach ((new AuthorizationSeams)->seams($config) as $binding) {
            $rows[$binding->abstract] = $binding;
        }

        return $rows;
    }

    /**
     * The application under test.
     *
     * @return \Illuminate\Foundation\Application
     */
    private function application(): Application
    {
        return $this->app ?? self::fail('The application has not booted.');
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
        return $this->application()->make(MandatorySeamsCheck::class);
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
        return $this->application()->make(ContextKeyCatalogue::class);
    }

    /**
     * Resolve the abstract, as anything that asks for it does.
     *
     * @param  string  $abstract
     * @return mixed
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function resolved(string $abstract): mixed
    {
        return $this->application()->make($abstract);
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
}
