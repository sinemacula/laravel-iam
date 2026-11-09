<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Providers;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;

/**
 * An application's provider that registers `laravel-authorization`'s provider
 * from its own `boot()`, once the application's booting callbacks have run but
 * before it has finished booting, so the member binds its defaults, with a
 * plain `bind()`, only then.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RegistersAuthorizationWhileBooting extends ServiceProvider
{
    /**
     * Register `laravel-authorization`'s provider.
     *
     * @return void
     */
    public function boot(): void
    {
        $this->app->register(AuthorizationServiceProvider::class);
    }
}
