<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Storage;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Iam\Storage\StorageConnection;

/**
 * Names another shared storage connection in `boot()`, after alignment.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ChangesTheSharedConnectionWhileBooting extends ServiceProvider
{
    /** @var string The connection the application names instead. */
    public const string CONNECTION = 'testing';

    /**
     * Name the other shared connection.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function boot(): void
    {
        $this->app->make(Repository::class)->set(StorageConnection::KEY, self::CONNECTION);
    }
}
