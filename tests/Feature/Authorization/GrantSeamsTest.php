<?php

declare(strict_types = 1);

namespace Tests\Feature\Authorization;

use Illuminate\Support\Facades\Config;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Contracts\GrantHook;
use SineMacula\Laravel\Authorization\Contracts\IdentityDirectory;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Hooks\GrantHooks;
use SineMacula\Laravel\Authorization\Hooks\GrantWidening;
use SineMacula\Laravel\Authorization\Hooks\ListedGrantHooks;
use SineMacula\Laravel\Authorization\Resolvers\FlatTenantTree;
use SineMacula\Laravel\Authorization\Resolvers\GuardUserIdentityDirectory;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Iam\Authorization\AuthorizationSeams;
use SineMacula\Laravel\Iam\Authorization\GrantHookAdapter;
use SineMacula\Laravel\Iam\Authorization\IdentityDirectoryAdapter;
use SineMacula\Laravel\Iam\Bindings\BindingOutcome;
use SineMacula\Laravel\Iam\Checks\MandatorySeamsCheck;
use SineMacula\Laravel\Iam\Sso\SsoSeams;
use Tests\Concerns\PermutesProviderOrder;
use Tests\Concerns\RunsChecks;
use Tests\Fixtures\Authorization\NamedIdentityDirectory;
use Tests\Fixtures\Authorization\RecordingGrantHook;
use Tests\TestCase;

/**
 * Feature tests for the seams `laravel-authorization` reads the grants through
 * (IAM-6.7, IAM-6.8): its identity directory and its grant hook, each bound
 * over `laravel-authorization`'s unconditional default in every provider order,
 * none over a class the application names in `laravel-authorization`'s
 * configuration or a binding it makes (IAM-8.4); the grant hook follows the SSO
 * capability's switch too, is bound over the composite whatever hooks the
 * application lists, which `laravel-authorization` runs once, before it, and is
 * mandatory while SSO's linking by a verified domain is on; the tenant tree is
 * left to the application; and an identity the hook cannot resolve refuses the
 * grant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationSeams::class)]
#[CoversClass(GrantHookAdapter::class)]
final class GrantSeamsTest extends TestCase
{
    use PermutesProviderOrder, RunsChecks;

    /** @var array<class-string, class-string> Each seam, with the adapter bound over it. */
    private const array ADAPTERS = [
        IdentityDirectory::class => IdentityDirectoryAdapter::class,
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
     * lists in `laravel-authorization`'s configuration, in every provider
     * order: `laravel-authorization` wraps the adapter in the listed hooks,
     * which run once, before it, and `iam:check` passes the adapter while SSO
     * links by a verified domain.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideProviderOrders')]
    public function testTheGrantHookIsBoundWhateverHooksAreListed(array $providers): void
    {
        $this->authorization = ['grant_hooks' => [RecordingGrantHook::class]];

        $this->bootInOrder($providers);

        $app      = $this->app ?? self::fail('The application has not booted.');
        $listed   = new RecordingGrantHook;
        $identity = new Reference('no-such-identity', '1');
        $widening = GrantWidening::of(new Operation('operation-1', null, new \DateTimeImmutable), $identity, $identity, [], new \DateTimeImmutable);

        $app->instance(RecordingGrantHook::class, $listed);
        $app->make('config')->set(AuthorizationSeams::DOMAIN_LINKING, true);

        $hook = $this->resolved(GrantHook::class);

        self::assertInstanceOf(ListedGrantHooks::class, $hook);
        self::assertSame([], $this->grantHookProblems());

        $hook->beforeWidening($widening);

        self::assertSame([$widening], $listed->widenings);
    }

    /**
     * An identity directory the application names in `laravel-authorization`'s
     * configuration wins in every provider order, `laravel-authorization`
     * binding it over the adapter where this package registered first, and
     * `iam:check` passes it.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testAClassTheApplicationNamesInAuthorizationsConfigurationIsKept(array $providers): void
    {
        $this->authorization = ['identity_directory' => NamedIdentityDirectory::class];

        $this->bootInOrder($providers);

        self::assertInstanceOf(NamedIdentityDirectory::class, $this->resolved(IdentityDirectory::class));
        self::assertInstanceOf(GrantHookAdapter::class, $this->resolved(GrantHook::class));

        $check = $this->app?->make(MandatorySeamsCheck::class) ?? self::fail('The application has not booted.');

        self::assertSame([], self::problems($check->checks()));
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

        $this->bootInOrder($providers, after: [GrantHook::class => $hook, IdentityDirectory::class => NamedIdentityDirectory::class]);

        self::assertSame($hook, $this->resolved(GrantHook::class));
        self::assertInstanceOf(NamedIdentityDirectory::class, $this->resolved(IdentityDirectory::class));
    }

    /**
     * With the SSO capability's switch off, the grant hook keeps
     * `laravel-authorization`'s composite, while the directory is bound.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[WithConfig(SsoSeams::SWITCH, false, defer: false)]
    public function testWithTheSsoSwitchOffTheGrantHookIsLeftAlone(): void
    {
        self::assertInstanceOf(GrantHooks::class, $this->resolved(GrantHook::class));
        self::assertInstanceOf(IdentityDirectoryAdapter::class, $this->resolved(IdentityDirectory::class));
    }

    /**
     * The tenant tree is left to the application: nothing is bound over
     * `laravel-authorization`'s flat default.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheTreeIsLeftToTheApplication(): void
    {
        $outcome = $this->app?->make(BindingOutcome::class);

        self::assertInstanceOf(BindingOutcome::class, $outcome);
        self::assertNotContains(TenantTree::class, $outcome->bound);
        self::assertInstanceOf(FlatTenantTree::class, $this->resolved(TenantTree::class));
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
        $app = $this->app ?? self::fail('The application has not booted.');

        self::assertSame([], $this->grantHookProblems());

        $app->bind(GrantHook::class, GrantHooks::class);

        self::assertNotSame([], $this->grantHookProblems());
    }

    /**
     * A widening of an identity whose type names no `laravel-authentication`
     * identity, which SSO never links, is not reported to SSO, nor refused: the
     * hooks the application lists once the application has booted still run for
     * it, once, as the grant service wraps the adapter in them.
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

        ListedGrantHooks::wrap($hook, $this->app ?? self::fail('The application has not booted.'))->beforeWidening($widening);

        self::assertSame([$widening], $listed->widenings);
    }

    /**
     * Load the application's configuration, then set what the test names in
     * `laravel-authorization`'s configuration before any provider registers.
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
     * Every problem `iam:check`'s mandatory seams check reports of the grant
     * hook.
     *
     * @return list<string>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function grantHookProblems(): array
    {
        $check = $this->app?->make(MandatorySeamsCheck::class) ?? self::fail('The application has not booted.');

        return array_values(array_filter(self::problems($check->checks()), static fn (string $problem): bool => str_contains($problem, GrantHook::class)));
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
