<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Providers;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Iam\IamServiceProvider;

/**
 * An application's provider that registers this package's provider from its own
 * `boot()`, once the application's booting callbacks have run but before it has
 * finished booting.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RegistersIamWhileBooting extends ServiceProvider
{
    /**
     * Register this package's provider.
     *
     * @return void
     */
    public function boot(): void
    {
        $this->app->register(IamServiceProvider::class);
    }
}
