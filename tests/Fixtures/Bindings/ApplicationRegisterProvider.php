<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Bindings;

use Illuminate\Support\ServiceProvider;
use Tests\Fixtures\Bindings\Contracts\ClosureSeam;
use Tests\Fixtures\Bindings\Contracts\PlainSeam;
use Tests\Fixtures\Bindings\Contracts\SharedSeam;

/**
 * An application's provider that binds its own implementation of every fixture
 * seam in `register()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ApplicationRegisterProvider extends ServiceProvider
{
    /**
     * Bind the application's implementations.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        $this->app->bind(PlainSeam::class, ApplicationImplementation::class);
        $this->app->singleton(SharedSeam::class, ApplicationImplementation::class);
        $this->app->bind(ClosureSeam::class, static fn (): ApplicationImplementation => new ApplicationImplementation);
    }
}
