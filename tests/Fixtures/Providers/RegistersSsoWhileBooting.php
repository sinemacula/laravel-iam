<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Providers;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Sso\SsoServiceProvider;

/**
 * An application's provider that registers `laravel-sso`'s provider from its
 * own `boot()`, once the application's booting callbacks have run but before it
 * has finished booting, so the member merges its configuration only then.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RegistersSsoWhileBooting extends ServiceProvider
{
    /**
     * Register `laravel-sso`'s provider.
     *
     * @return void
     */
    public function boot(): void
    {
        $this->app->register(SsoServiceProvider::class);
    }
}
