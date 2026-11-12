<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Storage;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\ServiceProvider;

/**
 * Points laravel-mfa's storage connection elsewhere in `boot()`.
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
