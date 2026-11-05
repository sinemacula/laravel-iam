<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Storage;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Iam\Storage\StorageConnection;

/**
 * An application's provider that names another shared storage connection in its
 * `boot()`, once every member key has been aligned in the booting phase.
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
