<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Providers;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Sso\SsoServiceProvider;

/**
 * An application's provider that registers `laravel-sso`'s provider only once
 * the application has booted, from a callback its `boot()` queues for then.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RegistersSsoOnceBooted extends ServiceProvider
{
    /**
     * Queue the registration of `laravel-sso`'s provider for once the
     * application has booted.
     *
     * @return void
     */
    public function boot(): void
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        $app->booted(static function (Application $app): void {
            $app->register(SsoServiceProvider::class);
        });
    }
}
