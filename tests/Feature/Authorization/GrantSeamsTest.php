<?php

declare(strict_types = 1);

namespace Tests\Feature\Authorization;

use Illuminate\Support\Facades\Config;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
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
use SineMacula\Laravel\Iam\Checks\MandatorySeamsCheck;
use SineMacula\Laravel\Iam\Sso\SsoSeams;
use Tests\Concerns\RunsChecks;
use Tests\Fixtures\Authorization\NamedIdentityDirectory;
use Tests\Fixtures\Authorization\RecordingGrantHook;
use Tests\TestCase;

/**
 * Feature tests for the identity directory and grant hook seams.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GrantHookAdapter::class)]
final class GrantSeamsTest extends TestCase
{
    use RunsChecks;

    /** @var array<string, mixed> What the application sets in `laravel-authorization`'s configuration before any provider registers. */
    private array $authorization = [];

    /**
     * The grant hook is bound, and listed hooks run once before it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheGrantHookIsBoundWhateverHooksAreListed(): void
    {
        $this->authorization = ['grant_hooks' => [RecordingGrantHook::class]];

        $this->refreshApplication();

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
     * A directory named in authorization's config is kept by `iam:check`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testADirectoryNamedInAuthorizationsConfigurationIsKept(): void
    {
        $this->authorization = ['identity_directory' => NamedIdentityDirectory::class];

        $this->refreshApplication();

        self::assertInstanceOf(NamedIdentityDirectory::class, $this->resolved(IdentityDirectory::class));
        self::assertInstanceOf(GrantHookAdapter::class, $this->resolved(GrantHook::class));

        $check = $this->app?->make(MandatorySeamsCheck::class) ?? self::fail('The application has not booted.');

        self::assertSame([], self::problems($check->checks()));
    }

    /**
     * With SSO's switch off the grant hook keeps the composite.
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
     * The tenant tree is left to the application.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheTreeIsLeftToTheApplication(): void
    {
        self::assertInstanceOf(FlatTenantTree::class, $this->resolved(TenantTree::class));
    }

    /**
     * With the switch off nothing is bound.
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
     * With linking by a verified domain on, `iam:check` passes the adapter.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[WithConfig(AuthorizationSeams::DOMAIN_LINKING, true, defer: false)]
    public function testIamCheckPassesTheAdapterWhileDomainLinkingIsOn(): void
    {
        self::assertSame([], $this->grantHookProblems());
    }

    /**
     * With domain linking on, `iam:check` refuses the composite.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[WithConfig(AuthorizationSeams::DOMAIN_LINKING, true, defer: false)]
    #[WithConfig(SsoSeams::SWITCH, false, defer: false)]
    public function testIamCheckRefusesTheCompositeWhileDomainLinkingIsOn(): void
    {
        self::assertCount(1, $this->grantHookProblems());
    }

    /**
     * Another identity kind is passed over and the listed hooks still run.
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
     * The mandatory seams check's problems with the grant hook.
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
