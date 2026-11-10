<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Authorization;

use SineMacula\Laravel\Authentication\Contracts\TenantResolver;

/**
 * Resolves every tenant id to a tenant `laravel-authorization` cannot scope to
 * (`UnscopedTenant`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class UnscopedTenancy implements TenantResolver
{
    /**
     * The tenant the id names.
     *
     * @param  string  $tenantId
     * @return \Tests\Fixtures\Authorization\UnscopedTenant
     */
    #[\Override]
    public function resolve(string $tenantId): UnscopedTenant
    {
        return new UnscopedTenant($tenantId);
    }
}
