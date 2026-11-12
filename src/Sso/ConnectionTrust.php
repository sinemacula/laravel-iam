<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Sso\Contracts\Enforcement;
use SineMacula\Laravel\Sso\Models\Connection;

/**
 * Whether a tenant trusts an SSO connection on an application: the tenant's
 * own, or one its enforcement names.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ConnectionTrust
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Resolves SSO's enforcement on each call. */
        private Container $container,
    ) {}

    /**
     * Whether the tenant trusts the connection on the application.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  string  $application
     * @return bool
     */
    public function trusts(string $tenantId, string $connectionId, string $application): bool
    {
        if (self::tenantOf($connectionId) === $tenantId) {
            return true;
        }

        return in_array($connectionId, $this->container->make(Enforcement::class)->policy($tenantId, $application)->connectionIds, true);
    }

    /**
     * The tenant SSO records for the connection, read on the write connection.
     *
     * @param  string  $connectionId
     * @return ?string
     */
    private static function tenantOf(string $connectionId): ?string
    {
        $connection = Connection::query()->useWritePdo()->whereKey($connectionId)->first();

        return $connection?->getTenantId();
    }
}
