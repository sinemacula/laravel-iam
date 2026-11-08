<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Providers;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\AuditLog\AuditLogServiceProvider;

/**
 * An application's provider that registers `laravel-audit-log`'s provider from
 * its own `boot()`, once this package's provider has booted but before the
 * application has finished booting, so audit-log binds its registries, and
 * queues their freeze, only then.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RegistersAuditLogWhileBooting extends ServiceProvider
{
    /**
     * Register `laravel-audit-log`'s provider.
     *
     * @return void
     */
    public function boot(): void
    {
        $this->app->register(AuditLogServiceProvider::class);
    }
}
