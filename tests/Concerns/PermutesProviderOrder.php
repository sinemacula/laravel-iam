<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Contracts\Foundation\Application;
use SineMacula\Laravel\AuditLog\AuditLogServiceProvider;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Iam\IamServiceProvider;
use SineMacula\Laravel\Mfa\MfaServiceProvider;
use SineMacula\Laravel\Sso\SsoServiceProvider;

/**
 * Boots the application with this package's provider first, last and between
 * the members', with the application's own bindings made before any provider
 * registers or once every provider has registered, as an application provider's
 * `register()` makes them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \Tests\TestCase
 */
trait PermutesProviderOrder
{
    /** @var array<string, \Closure|object|string> The bindings the application makes before any provider registers. */
    private array $bindingsBefore = [];

    /** @var array<string, \Closure|object|string> The bindings the application makes once every provider has registered. */
    private array $bindingsAfter = [];

    /**
     * Rows of `[providers]`: this package first, last, where package discovery
     * puts it (the members' package names sorted, `laravel-iam` among them),
     * and between the members registered in reverse.
     *
     * @return iterable<string, array{0: list<class-string<\Illuminate\Support\ServiceProvider>>}>
     */
    public static function provideProviderOrders(): iterable
    {
        yield 'this package first' => [[
            IamServiceProvider::class,
            AuthenticationServiceProvider::class,
            AuthorizationServiceProvider::class,
            MfaServiceProvider::class,
            SsoServiceProvider::class,
            AuditLogServiceProvider::class,
        ]];

        yield 'this package last' => [[
            AuthenticationServiceProvider::class,
            AuthorizationServiceProvider::class,
            MfaServiceProvider::class,
            SsoServiceProvider::class,
            AuditLogServiceProvider::class,
            IamServiceProvider::class,
        ]];

        yield 'discovery order' => [[
            AuditLogServiceProvider::class,
            AuthenticationServiceProvider::class,
            AuthorizationServiceProvider::class,
            IamServiceProvider::class,
            MfaServiceProvider::class,
            SsoServiceProvider::class,
        ]];

        yield 'members reversed around this package' => [[
            SsoServiceProvider::class,
            MfaServiceProvider::class,
            IamServiceProvider::class,
            AuthorizationServiceProvider::class,
            AuthenticationServiceProvider::class,
            AuditLogServiceProvider::class,
        ]];
    }

    /**
     * Boot a new application with the providers in the given order, and the
     * application's own bindings in `$before`, made before any provider
     * registers, and in `$after`, made once every provider has registered and
     * before any boots. A closure or class name is bound; any other object is
     * bound as an instance.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @param  array<string, \Closure|object|string>  $before
     * @param  array<string, \Closure|object|string>  $after
     * @return void
     */
    protected function bootInOrder(array $providers, array $before = [], array $after = []): void
    {
        $this->bindingsBefore = $before;
        $this->bindingsAfter  = $after;

        $this->reorderProviders($providers);
    }

    /**
     * Prepare the application's core, then make the application's bindings that
     * come first: Testbench prepares the core before it loads the configuration
     * and registers any provider.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function resolveApplicationCore(mixed $app): void
    {
        parent::resolveApplicationCore($app);

        self::bindForApplication($app, $this->bindingsBefore);
    }

    /**
     * Seed the environment, then make the application's bindings that come
     * last: Testbench defines the environment once every provider has
     * registered and before any boots, where an application provider's
     * `register()` would bind.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        self::bindForApplication($app, $this->bindingsAfter);
    }

    /**
     * Make each of the application's bindings: a closure or class name is
     * bound, and any other object bound as an instance.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @param  array<string, \Closure|object|string>  $bindings
     * @return void
     */
    private static function bindForApplication(Application $app, array $bindings): void
    {
        foreach ($bindings as $abstract => $concrete) {

            if (is_object($concrete) && !$concrete instanceof \Closure) {
                $app->instance($abstract, $concrete);

                continue;
            }

            $app->bind($abstract, $concrete);
        }
    }
}
