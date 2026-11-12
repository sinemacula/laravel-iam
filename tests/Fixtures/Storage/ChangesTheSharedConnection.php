<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Storage;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Iam\Storage\StorageConnection;

/**
 * Names another shared storage connection in `register()`, after this package.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ChangesTheSharedConnection extends ServiceProvider
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
    #[\Override]
    public function register(): void
    {
        $this->app->make(Repository::class)->set(StorageConnection::KEY, self::CONNECTION);
    }
}
