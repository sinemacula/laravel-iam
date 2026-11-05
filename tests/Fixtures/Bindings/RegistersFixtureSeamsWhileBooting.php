<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Bindings;

use Illuminate\Support\ServiceProvider;

/**
 * An application's provider that registers the fixture rule from its own
 * `boot()`, once the application's booting callbacks have run but before it has
 * finished booting.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RegistersFixtureSeamsWhileBooting extends ServiceProvider
{
    /**
     * Register the fixture rule.
     *
     * @return void
     */
    public function boot(): void
    {
        $this->app->register(FixtureSeamsProvider::class);
    }
}
