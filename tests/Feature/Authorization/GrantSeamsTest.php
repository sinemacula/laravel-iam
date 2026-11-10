<?php

declare(strict_types = 1);

namespace Tests\Feature\Authorization;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Config;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Contracts\GrantHook;
use SineMacula\Laravel\Authorization\Contracts\IdentityDirectory;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Hooks\GrantHooks;
use SineMacula\Laravel\Authorization\Hooks\GrantWidening;
use SineMacula\Laravel\Authorization\Resolvers\FlatTenantTree;
use SineMacula\Laravel\Authorization\Resolvers\GuardUserIdentityDirectory;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Iam\Authorization\AuthorizationSeams;
use SineMacula\Laravel\Iam\Authorization\GrantHookAdapter;
use SineMacula\Laravel\Iam\Authorization\IdentityDirectoryAdapter;
use SineMacula\Laravel\Iam\Authorization\TenantTreeAdapter;
use SineMacula\Laravel\Iam\Bindings\BindingOutcome;
use SineMacula\Laravel\Iam\Bindings\BindingRule;
use SineMacula\Laravel\Iam\Bindings\Enums\Lifetime;
use SineMacula\Laravel\Iam\Checks\MandatorySeamsCheck;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Sso\SsoSeams;
use SineMacula\Laravel\Iam\Tenancy\TenancyContracts;
use SineMacula\Laravel\Iam\Testing\FakeTenantTree;
use Tests\Concerns\PermutesProviderOrder;
use Tests\Concerns\RunsChecks;
use Tests\Fixtures\Authorization\NamedIdentityDirectory;
use Tests\Fixtures\Authorization\NamedTenantTree;
use Tests\Fixtures\Authorization\RecordingGrantHook;
use Tests\TestCase;

/**
 * Feature tests for the seams `laravel-authorization` reads the grants and the
 * tree through (IAM-6.7, IAM-6.8, IAM-7.5): its identity directory, its tenant
 * tree and its grant hook, each bound over `laravel-authorization`'s
 * unconditional default in every provider order, none over a class the
 * application names in `laravel-authorization`'s configuration or a binding it
 * makes (IAM-8.4); the grant hook follows the SSO capability's switch too, is
 * bound over the composite whatever hooks the application lists, and is
 * mandatory while SSO's linking by a verified domain is on; the tree is the
 * adapter only while the application names or binds a tree, and
 * `laravel-authorization`'s own flat tree otherwise; and an identity the hook
 * cannot resolve refuses the grant. The application names a tree unless a test
 * says otherwise.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationSeams::class)]
#[CoversClass(GrantHookAdapter::class)]
#[CoversClass(TenantTreeAdapter::class)]
#[WithConfig(TenancyContracts::TREE, FakeTenantTree::class, defer: false)]
final class GrantSeamsTest extends TestCase
{
    use PermutesProviderOrder, RunsChecks;

    /** @var array<class-string, class-string> Each seam, with the adapter bound over it. */
    private const array ADAPTERS = [
        IdentityDirectory::class => IdentityDirectoryAdapter::class,
        TenantTree::class        => TenantTreeAdapter::class,
        GrantHook::class         => GrantHookAdapter::class,
    ];

    /** @var array<string, mixed> What the application sets in `laravel-authorization`'s configuration before any provider registers. */
    private array $authorization = [];

    /**
     * Every adapter is bound over `laravel-authorization`'s default in every
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

        $outcome = $this->app?->make(BindingOutcome::class);

        self::assertInstanceOf(BindingOutcome::class, $outcome);
        self::assertSame(array_keys(self::ADAPTERS), array_values(array_intersect($outcome->bound, array_keys(self::ADAPTERS))));
    }

    /**
     * The grant hook is bound over the composite whatever hooks the application
     * lists in `laravel-authorization`'s configuration, which the adapter still
     * runs.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testTheGrantHookIsBoundWhateverHooksAreListed(array $providers): void
    {
        $this->authorization = ['grant_hooks' => [RecordingGrantHook::class]];

        $this->bootInOrder($providers);

        self::assertInstanceOf(GrantHookAdapter::class, $this->resolved(GrantHook::class));
    }

    /**
     * A tree and an identity directory the application names in
     * `laravel-authorization`'s configuration are kept in every provider order.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testAClassTheApplicationNamesInAuthorizationsConfigurationIsKept(array $providers): void
    {
        $this->authorization = ['tenant_tree' => NamedTenantTree::class, 'identity_directory' => NamedIdentityDirectory::class];

        $this->bootInOrder($providers);

        self::assertInstanceOf(NamedTenantTree::class, $this->resolved(TenantTree::class));
        self::assertInstanceOf(NamedIdentityDirectory::class, $this->resolved(IdentityDirectory::class));
        self::assertInstanceOf(GrantHookAdapter::class, $this->resolved(GrantHook::class));
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
    public function testAnApplicationBindingWins(array $providers): void
    {
        $hook = new RecordingGrantHook;

        $this->bootInOrder($providers, after: [GrantHook::class => $hook, TenantTree::class => NamedTenantTree::class]);

        self::assertSame($hook, $this->resolved(GrantHook::class));
        self::assertInstanceOf(NamedTenantTree::class, $this->resolved(TenantTree::class));
    }

    /**
     * With the SSO capability's switch off, the grant hook keeps
     * `laravel-authorization`'s composite, while the directory and the tree are
     * bound.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[WithConfig(SsoSeams::SWITCH, false, defer: false)]
    public function testWithTheSsoSwitchOffTheGrantHookIsLeftAlone(): void
    {
        self::assertInstanceOf(GrantHooks::class, $this->resolved(GrantHook::class));
        self::assertInstanceOf(TenantTreeAdapter::class, $this->resolved(TenantTree::class));
    }

    /**
     * While the application neither names nor binds a tree, the seam is
     * `laravel-authorization`'s own flat tree, which it tells a flat
     * application by, though the row is bound; a tree bound later is the
     * adapter's from the next unit of work, and one taken away is flat again.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[WithConfig(TenancyContracts::TREE, null, defer: false)]
    public function testWithoutATreeTheMembersFlatTreeIsTheSeam(): void
    {
        $outcome = $this->app?->make(BindingOutcome::class);
        $flat    = $this->resolved(TenantTree::class);

        self::assertInstanceOf(BindingOutcome::class, $outcome);
        self::assertContains(TenantTree::class, $outcome->bound);
        self::assertInstanceOf(FlatTenantTree::class, $flat);

        FakeTenantTree::fake($this->app);

        self::assertSame($flat, $this->resolved(TenantTree::class));

        Iam::resetWorkerState();

        self::assertSame(TenantTreeAdapter::class, $this->treeClass());

        $this->app?->forgetInstance(FakeTenantTree::TREE);

        Iam::resetWorkerState();

        self::assertSame(FlatTenantTree::class, $this->treeClass());
    }

    /**
     * With the authorization capability's switch off, nothing is bound.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[WithConfig(AuthorizationSeams::SWITCH, false, defer: false)]
    public function testWithTheSwitchOffNothingIsBound(): void
    {
        $this->assertResolvesTo([
            IdentityDirectory::class => GuardUserIdentityDirectory::class,
            TenantTree::class        => FlatTenantTree::class,
            GrantHook::class         => GrantHooks::class,
        ]);
    }

    /**
     * Grants are reported to SSO's scope widening only while both the
     * authorization and the SSO capabilities' switches are on, as the grant
     * hook's row applies.
     *
     * @return void
     */
    public function testGrantsAreReportedToSsoOnlyWhileBothSwitchesAreOn(): void
    {
        $config  = $this->app?->make('config') ?? self::fail('The application has not booted.');
        $reports = [];

        foreach ([[true, true], [true, false], [false, true]] as [$authorization, $sso]) {

            $config->set(AuthorizationSeams::SWITCH, $authorization);
            $config->set(SsoSeams::SWITCH, $sso);

            $reports[] = AuthorizationSeams::reportsWidenings($config);
        }

        self::assertSame([true, false, false], $reports);
    }

    /**
     * The grant hook's binding is mandatory while SSO's linking by a verified
     * domain is on, and not otherwise.
     *
     * @return void
     */
    public function testTheGrantHookIsMandatoryWhileDomainLinkingIsOn(): void
    {
        $config = $this->app?->make('config') ?? self::fail('The application has not booted.');
        $rows   = [];

        foreach ([false, true] as $isOn) {

            $config->set(AuthorizationSeams::DOMAIN_LINKING, $isOn);

            foreach ((new AuthorizationSeams)->seams($config) as $row) {
                if ($row->abstract !== GrantHook::class) {
                    continue;
                }

                $rows[] = $row->isMandatory();
            }
        }

        self::assertSame([false, true], $rows);
    }

    /**
     * With linking by a verified domain on, `iam:check` passes the adapter and
     * refuses `laravel-authorization`'s composite the application bound back.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[WithConfig(AuthorizationSeams::DOMAIN_LINKING, true, defer: false)]
    public function testIamCheckRefusesTheCompositeWhileDomainLinkingIsOn(): void
    {
        $app   = $this->app ?? self::fail('The application has not booted.');
        $check = $app->make(MandatorySeamsCheck::class);

        self::assertSame([], array_values(array_filter(self::problems($check->checks()), static fn (string $problem): bool => str_contains($problem, GrantHook::class))));

        $app->bind(GrantHook::class, GrantHooks::class);

        self::assertNotSame([], array_values(array_filter(self::problems($check->checks()), static fn (string $problem): bool => str_contains($problem, GrantHook::class))));
    }

    /**
     * The tree is held under this package's own scoped key: one instance for a
     * unit of work, as `laravel-authorization` keeps the request's tenant chain
     * only while the tree bound is the instance it read it from, forgotten by
     * the worker reset, and the seam itself never scoped; the directory and the
     * hook stay transient.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheTreeIsOneForAUnitOfWork(): void
    {
        $app   = $this->app ?? self::fail('The application has not booted.');
        $first = $this->resolved(TenantTree::class);
        $rows  = [];

        foreach ((new AuthorizationSeams)->seams($app->make('config')) as $row) {
            $rows[$row->abstract] = $row->lifetime;
        }

        self::assertInstanceOf(TenantTreeAdapter::class, $first);
        self::assertSame($first, $this->resolved(TenantTree::class));
        self::assertTrue($app->bound(BindingRule::SCOPED_PREFIX . TenantTree::class));
        self::assertFalse($app->isShared(TenantTree::class));
        self::assertSame([Lifetime::SCOPED, Lifetime::TRANSIENT, Lifetime::TRANSIENT], [$rows[TenantTree::class], $rows[IdentityDirectory::class], $rows[GrantHook::class]]);

        Iam::resetWorkerState();

        self::assertNotSame($first, $this->resolved(TenantTree::class));
    }

    /**
     * A widening of an identity whose type names no `laravel-authentication`
     * identity, which SSO never links, is not reported to SSO, nor refused: the
     * hooks the application lists still run for it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityOfAnotherKindIsPassedOverAndTheListedHooksRun(): void
    {
        $listed   = new RecordingGrantHook;
        $identity = new Reference('no-such-identity', '1');
        $widening = GrantWidening::of(new Operation('operation-1', null, new \DateTimeImmutable), $identity, $identity, [], new \DateTimeImmutable);

        $this->app?->instance(RecordingGrantHook::class, $listed);

        Config::set('authorization.grant_hooks', [RecordingGrantHook::class]);

        $hook = $this->resolved(GrantHook::class);

        self::assertInstanceOf(GrantHookAdapter::class, $hook);

        $hook->beforeWidening($widening);

        self::assertSame([$widening], $listed->widenings);
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
     * The class of the tree `laravel-authorization` reads now.
     *
     * @return string
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function treeClass(): string
    {
        $tree = $this->resolved(TenantTree::class);

        return is_object($tree) ? $tree::class : '';
    }

    /**
     * Resolve the abstract from the application under test.
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
