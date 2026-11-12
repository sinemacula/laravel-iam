<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Tenancy;

use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;

/**
 * A tenant resolver that reads the landlord model without pinning.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FindsLandlordTenants implements TenantResolver
{
    /**
     * The landlord's tenant of the id, as the connection reads it, or `null`.
     *
     * @param  string  $tenantId
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Tenant
     */
    #[\Override]
    public function resolve(string $tenantId): ?Tenant
    {
        return LandlordTenant::query()->find($tenantId);
    }
}
