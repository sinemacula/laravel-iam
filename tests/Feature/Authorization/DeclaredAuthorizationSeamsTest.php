<?php

declare(strict_types = 1);

namespace Tests\Feature\Authorization;

use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Artisan;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationContext;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker;
use SineMacula\Laravel\Authorization\Contracts\GrantHook;
use SineMacula\Laravel\Authorization\Contracts\IdentityDirectory;
use SineMacula\Laravel\Authorization\Contracts\SessionPolicySource;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Diagnostics\Declarations;
use SineMacula\Laravel\Authorization\Resolvers\FlatTenantTree;
use SineMacula\Laravel\Iam\Authorization\AuthenticationContextAdapter;
use SineMacula\Laravel\Iam\Authorization\AuthorizationSeams;
use SineMacula\Laravel\Iam\Authorization\GrantHookAdapter;
use SineMacula\Laravel\Iam\Authorization\IdentityDirectoryAdapter;
use SineMacula\Laravel\Iam\Authorization\RequirementCheckerAdapter;
use SineMacula\Laravel\Iam\Authorization\SessionPolicySourceAdapter;
use SineMacula\Laravel\Iam\Authorization\SubjectResolverAdapter;
use SineMacula\Laravel\Iam\Authorization\TenantTreeAdapter;
use SineMacula\Laravel\Iam\Bindings\BindingRule;
use SineMacula\Laravel\Iam\Bindings\Enums\Lifetime;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Iam\IamServiceProvider;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use SineMacula\Laravel\Iam\Sso\SsoSeams;
use Tests\Concerns\PermutesProviderOrder;
use Tests\Fixtures\Authorization\NamedSubjectResolver;
use Tests\Fixtures\Authorization\NamedTenantTree;
use Tests\TestCase;

/**
 * Feature tests for the declaration of each adapter bound over one of
 * `laravel-authorization`'s contracts to its configuration report: in every
 * provider order, `authorization:check` names each as declared by
 * `laravel-iam`, with its class, or the tree's two classes and when its factory
 * decides, and its lifetime, and the closure declared is the one bound over the
 * contract; a binding made over an adapter afterwards shows the declaration
 * overridden, and an instance bound over it shows that; and nothing is declared
 * over the application's own binding, over a class the application names in
 * `laravel-authorization`'s configuration where it was bound first, for a row
 * whose switch is off, or at all while the capability's switch is.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationSeams::class)]
#[CoversClass(BindingRule::class)]
#[CoversClass(SeamBinding::class)]
#[CoversClass(Lifetime::class)]
final class DeclaredAuthorizationSeamsTest extends TestCase
{
    use PermutesProviderOrder;

    /** @var array<class-string, array{list<class-string>, ?string, string}> Each contract declared, with the classes declared, when a factory decides, and the lifetime. */
    private const array DECLARED = [
        SubjectResolver::class                  => [[SubjectResolverAdapter::class], null, 'scoped'],
        AuthenticationContext::class            => [[AuthenticationContextAdapter::class], null, 'transient'],
        AuthenticationRequirementChecker::class => [[RequirementCheckerAdapter::class], null, 'transient'],
        SessionPolicySource::class              => [[SessionPolicySourceAdapter::class], null, 'transient'],
        IdentityDirectory::class                => [[IdentityDirectoryAdapter::class], null, 'transient'],
        TenantTree::class                       => [[TenantTreeAdapter::class, FlatTenantTree::class], AuthorizationSeams::DECIDES, 'scoped'],
        GrantHook::class                        => [[GrantHookAdapter::class], null, 'transient'],
    ];

    /** @var array<string, mixed> What the application sets in `laravel-authorization`'s configuration before any provider registers. */
    private array $authorization = [];

    /**
     * In every provider order, each adapter is declared by `laravel-iam` with
     * the very closure bound over its contract, and `authorization:check` names
     * it as declared, its declaration standing, and passes.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \JsonException
     */
    #[DataProvider('provideProviderOrders')]
    public function testEveryAdapterIsDeclaredAndStandsInEveryProviderOrder(array $providers): void
    {
        $this->bootInOrder($providers);

        $app          = $this->application();
        $declarations = Declarations::of($app);

        self::assertSame(array_keys(self::DECLARED), array_keys($declarations->all()));

        foreach (array_keys(self::DECLARED) as $contract) {
            self::assertSame($app->getBindings()[$contract]['concrete'], $declarations->for($contract)?->binding, $contract);
        }

        [$exit, $seams] = $this->report();

        self::assertSame(0, $exit);

        foreach (self::DECLARED as $contract => [$classes, $decides, $lifetime]) {

            $seam = $seams[$contract];

            self::assertSame('declared', $seam['origin'], $contract);
            self::assertSame($classes, $seam['classes'], $contract);
            self::assertSame($decides, $seam['decides'], $contract);
            self::assertSame($lifetime, $seam['lifetime'], $contract);
            self::assertSame([
                'owner'    => AuthorizationSeams::OWNER,
                'classes'  => $classes,
                'decides'  => $decides,
                'lifetime' => $lifetime,
                'state'    => 'standing',
            ], $seam['declaration'], $contract);
        }
    }

    /**
     * The text report names the owner, the class, or the tree's classes and
     * when its factory decides, and the lifetime.
     *
     * @return void
     */
    public function testTheTextReportNamesLaravelIam(): void
    {
        $output = $this->text();

        self::assertStringContainsString('[seam SubjectResolver] declared by laravel-iam; ' . SubjectResolverAdapter::class . '; scoped', $output);
        self::assertStringContainsString('[seam AuthenticationContext] declared by laravel-iam; ' . AuthenticationContextAdapter::class . '; transient', $output);
        $tree = sprintf('one of %s, %s, decided at first resolution', TenantTreeAdapter::class, FlatTenantTree::class);

        self::assertStringContainsString('[seam TenantTree] declared by laravel-iam; ' . $tree . '; scoped', $output);
    }

    /**
     * In every provider order, a binding the application makes over each
     * adapter once every provider has registered shows the declaration
     * overridden.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \JsonException
     */
    #[DataProvider('provideProviderOrders')]
    public function testABindingMadeOverAnAdapterShowsItOverriddenInEveryProviderOrder(array $providers): void
    {
        $this->bootInOrder($providers, after: self::applicationBindings());

        [, $seams] = $this->report();

        foreach (array_keys(self::DECLARED) as $contract) {
            self::assertSame('later_binding', $seams[$contract]['origin'], $contract);
            self::assertSame('overridden', $seams[$contract]['declaration']['state'] ?? null, $contract);
        }

        self::assertStringContainsString('declared by laravel-iam as ' . SubjectResolverAdapter::class . ', but overridden later', $this->text());
    }

    /**
     * An instance bound over an adapter shows the declaration with an instance
     * bound over it.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAnInstanceBoundOverAnAdapterIsShown(): void
    {
        $app = $this->application();

        $app->instance(TenantTree::class, new FlatTenantTree);

        [, $seams] = $this->report();

        self::assertSame('instance_over_it', $seams[TenantTree::class]['declaration']['state'] ?? null);
        self::assertSame('standing', $seams[SubjectResolver::class]['declaration']['state'] ?? null);
    }

    /**
     * In every provider order, nothing is declared over a binding the
     * application makes before any provider registers, which the binding rule
     * keeps.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \JsonException
     */
    #[DataProvider('provideProviderOrders')]
    public function testNothingIsDeclaredOverAnApplicationBindingInEveryProviderOrder(array $providers): void
    {
        $this->bootInOrder($providers, before: self::applicationBindings());

        self::assertSame([], Declarations::of($this->application())->all());

        [, $seams] = $this->report();

        foreach (array_keys(self::DECLARED) as $contract) {
            self::assertNull($seams[$contract]['declaration'], $contract);
        }
    }

    /**
     * In every provider order, a class the application names in
     * `laravel-authorization`'s configuration is reported as configured: where
     * `laravel-authorization` registered first, the binding rule keeps it and
     * declares nothing; where this package registered first, the adapter it
     * bound and declared is overridden by the class.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \JsonException
     */
    #[DataProvider('provideProviderOrders')]
    public function testAConfiguredClassIsReportedAsConfiguredInEveryProviderOrder(array $providers): void
    {
        $this->authorization = ['subject_resolver' => NamedSubjectResolver::class, 'tenant_tree' => NamedTenantTree::class];

        $this->bootInOrder($providers);

        $first = array_search(AuthorizationServiceProvider::class, $providers, true) < array_search(IamServiceProvider::class, $providers, true);

        [, $seams] = $this->report();

        foreach ([SubjectResolver::class, TenantTree::class] as $contract) {
            self::assertSame('configured', $seams[$contract]['origin'], $contract);
            self::assertSame($first ? null : 'overridden', $seams[$contract]['declaration']['state'] ?? null, $contract);
        }

        self::assertSame('standing', $seams[AuthenticationContext::class]['declaration']['state'] ?? null);
    }

    /**
     * With the capability's switch off, nothing is declared, and the report
     * names no declaration.
     *
     * @return void
     *
     * @throws \JsonException
     */
    #[WithConfig(AuthorizationSeams::SWITCH, false, defer: false)]
    public function testWithTheSwitchOffNothingIsDeclared(): void
    {
        self::assertSame([], Declarations::of($this->application())->all());

        [, $seams] = $this->report();

        foreach (array_keys(self::DECLARED) as $contract) {
            self::assertNull($seams[$contract]['declaration'], $contract);
        }
    }

    /**
     * With the MFA and SSO capabilities' switches off, the requirement checker
     * and the grant hook, which follow them, are not declared, and the rest
     * are.
     *
     * @return void
     */
    #[WithConfig(MfaSeams::SWITCH, false, defer: false)]
    #[WithConfig(SsoSeams::SWITCH, false, defer: false)]
    public function testARowWhoseSwitchIsOffIsNotDeclared(): void
    {
        $declared = array_diff(array_keys(self::DECLARED), [AuthenticationRequirementChecker::class, GrantHook::class]);

        self::assertSame(array_values($declared), array_keys(Declarations::of($this->application())->all()));
    }

    /**
     * Set what the test names in `laravel-authorization`'s configuration before
     * any provider registers, as the application's own configuration would.
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
     * A binding of the application's own for each contract declared, each
     * building a stand-in for the contract, its authentication context naming
     * the namespace `laravel-authorization` checks it for as it boots.
     *
     * @return array<class-string, \Closure(): object>
     */
    private static function applicationBindings(): array
    {
        $bindings = [];

        foreach (array_keys(self::DECLARED) as $contract) {

            $instance = \Mockery::mock($contract);

            $instance->allows('namespaces')->andReturn(['authentication']);
            $instance->allows('assuranceKeys')->andReturn([]);

            $bindings[$contract] = static fn (): object => $instance;
        }

        return $bindings;
    }

    /**
     * Run `authorization:check` as JSON, and return its exit code and its
     * seams, keyed by contract.
     *
     * @return array{int, array<string, array<string, mixed>>}
     *
     * @throws \JsonException
     */
    private function report(): array
    {
        $exit   = Artisan::call('authorization:check', ['--format' => 'json']);
        $report = json_decode(Artisan::output(), true, flags: JSON_THROW_ON_ERROR);

        self::assertIsArray($report);
        self::assertIsArray($report['seams'] ?? null);

        $seams = [];

        foreach ($report['seams'] as $seam) {
            self::assertIsArray($seam);
            self::assertIsString($seam['contract'] ?? null);

            $seams[$seam['contract']] = $seam;
        }

        return [$exit, $seams];
    }

    /**
     * Run `authorization:check` as text, and return what it printed.
     *
     * @return string
     */
    private function text(): string
    {
        Artisan::call('authorization:check');

        return Artisan::output();
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
}
