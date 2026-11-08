<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Sso\Contracts\Enforcement;
use SineMacula\Laravel\Sso\Models\Connection;

/**
 * Whether a tenant trusts an SSO connection on an application: the connection
 * is the tenant's own (SSO's connection records its tenant), or the tenant's
 * enforcement on the application names it (`Contracts\Enforcement::policy()`,
 * as an inheriting tenant's rule names the enforcing tenant's connections). One
 * tenant's trust in a connection is never another's (IAM-4.6, SSO-8.7).
 *
 * It is asked by `ExternalEvidencePolicyAdapter` for a tenant's requirement,
 * and by the proof translator before it lets MFA see an external provider's
 * proof naming its connection, so both judge a tenant's trust the same way. The
 * connection is read on the write connection, without a lock, and SSO's
 * enforcement is resolved on each call, so nothing is kept between calls
 * (IAM-8.1) and asking under a session's row lock inverts nothing.
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
     * Whether the tenant trusts the connection on the application: it is the
     * tenant's own, or the tenant's enforcement on the application names it.
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
     * The tenant SSO records the connection as belonging to, read on the write
     * connection, or `null` when there is no such connection.
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
