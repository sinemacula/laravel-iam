<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Bindings;

use Illuminate\Support\ServiceProvider;
use Tests\Fixtures\Bindings\Contracts\ClosureSeam;
use Tests\Fixtures\Bindings\Contracts\PlainSeam;
use Tests\Fixtures\Bindings\Contracts\SharedSeam;

/**
 * An application's provider that binds its own implementation once and, in
 * `register()`, aliases every fixture seam to it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ApplicationAliasProvider extends ServiceProvider
{
    /**
     * Bind the application's implementation and alias every seam to it.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        $this->app->singleton(ApplicationImplementation::class);

        foreach ([PlainSeam::class, SharedSeam::class, ClosureSeam::class] as $seam) {
            $this->app->alias(ApplicationImplementation::class, $seam);
        }
    }
}
