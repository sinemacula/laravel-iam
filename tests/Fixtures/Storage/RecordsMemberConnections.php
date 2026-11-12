<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Storage;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Iam\Storage\StorageConnection;

/**
 * Records each member's storage connection as this provider registers.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordsMemberConnections extends ServiceProvider
{
    /** @var string The container key the recorded connections are kept under. */
    public const string RECORDED = 'tests.storage.recorded-connections';

    /**
     * Record each member key's value, keyed by the member key.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    public function register(): void
    {
        $config = $this->app->make(Repository::class);

        $this->app->instance(self::RECORDED, array_combine(
            StorageConnection::MEMBER_KEYS,
            array_map(static fn (string $key): mixed => $config->get($key), StorageConnection::MEMBER_KEYS),
        ));
    }
}
