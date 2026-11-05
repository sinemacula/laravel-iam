<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Storage;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\ServiceProvider;

/**
 * An application's provider that points `laravel-mfa`'s storage connection at
 * another connection in its `boot()`, once the storage connections have been
 * checked in the booting phase.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PointsMfaElsewhereWhileBooting extends ServiceProvider
{
    /** @var string The connection the member key is pointed at. */
    public const string CONNECTION = 'elsewhere';

    /**
     * Point the member key at the other connection.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function boot(): void
    {
        $this->app->make(Repository::class)->set('mfa.storage.connection', self::CONNECTION);
    }
}
