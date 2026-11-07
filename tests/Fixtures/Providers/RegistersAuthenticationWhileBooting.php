<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Providers;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;

/**
 * An application's provider that registers `laravel-authentication`'s provider
 * from its own `boot()`, once the application's booting callbacks have run but
 * before it has finished booting, so the member binds its authentication
 * context's contributors only then.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RegistersAuthenticationWhileBooting extends ServiceProvider
{
    /**
     * Register `laravel-authentication`'s provider.
     *
     * @return void
     */
    public function boot(): void
    {
        $this->app->register(AuthenticationServiceProvider::class);
    }
}
