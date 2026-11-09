<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Providers;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Authorization\Contracts\ContextKeyCatalogue;

/**
 * An application's provider that, as it boots, builds `laravel-authorization`'s
 * key catalogue and resolves its manager, as one declaring context keys of its
 * own or asking a check while it boots does, before the application has
 * finished booting.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ResolvesAuthorizationWhileBooting extends ServiceProvider
{
    /**
     * Build the key catalogue and resolve the manager.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function boot(): void
    {
        $this->app->make(ContextKeyCatalogue::class);
        $this->app->make('authorization');
    }
}
