<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Providers;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationContext;

/**
 * Records, as it boots, the class `laravel-authorization`'s authentication
 * context resolves to, so a test that registers it before every package
 * provider can tell this package bound `laravel-authorization`'s seams again
 * before the first provider booted, where `laravel-authorization`, registering
 * after this package, bound its own default over them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordsAuthorizationContextWhileBooting extends ServiceProvider
{
    /** @var string The container key the record is kept under. */
    public const string RECORDED = 'tests.providers.authorization-context-before-boot';

    /**
     * Record the class the authentication context resolves to.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function boot(): void
    {
        $this->app->instance(self::RECORDED, $this->app->make(AuthenticationContext::class)::class);
    }
}
