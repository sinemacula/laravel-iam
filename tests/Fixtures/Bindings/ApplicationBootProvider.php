<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Bindings;

use Illuminate\Support\ServiceProvider;
use Tests\Fixtures\Bindings\Contracts\ClosureSeam;
use Tests\Fixtures\Bindings\Contracts\PlainSeam;
use Tests\Fixtures\Bindings\Contracts\SharedSeam;

/**
 * An application's provider that binds its own implementation of every fixture
 * seam in `boot()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ApplicationBootProvider extends ServiceProvider
{
    /**
     * Bind the application's implementations.
     *
     * @return void
     */
    public function boot(): void
    {
        $this->app->bind(PlainSeam::class, ApplicationImplementation::class);
        $this->app->singleton(SharedSeam::class, ApplicationImplementation::class);
        $this->app->bind(ClosureSeam::class, static fn (): ApplicationImplementation => new ApplicationImplementation);
    }
}
