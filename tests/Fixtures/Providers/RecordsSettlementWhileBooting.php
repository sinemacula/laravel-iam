<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Providers;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Iam\Storage\StorageConnection;

/**
 * Records, as it boots, every member's storage connection, so a test that
 * registers it before every package provider can tell this package settled the
 * storage connections before the first provider booted.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordsSettlementWhileBooting extends ServiceProvider
{
    /** @var string The container key the record is kept under. */
    public const string RECORDED = 'tests.providers.settled-before-boot';

    /**
     * Record each member key's value, keyed by the member key.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function boot(): void
    {
        $config = $this->app->make(Repository::class);

        $this->app->instance(self::RECORDED, array_combine(
            StorageConnection::MEMBER_KEYS,
            array_map(static fn (string $key): mixed => $config->get($key), StorageConnection::MEMBER_KEYS),
        ));
    }
}
