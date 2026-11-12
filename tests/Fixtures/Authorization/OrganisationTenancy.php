<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Authorization;

use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;

/**
 * An open tenancy of organisations.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class OrganisationTenancy implements TenantAccess, TenantResolver
{
    /**
     * The organisation of the id.
     *
     * @param  string  $tenantId
     * @return \Tests\Fixtures\Authorization\Organisation
     */
    #[\Override]
    public function resolve(string $tenantId): Organisation
    {
        return new Organisation($tenantId);
    }

    /**
     * Every principal may act in any organisation, or in none.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return bool
     */
    #[\Override]
    public function mayActIn(Principal $principal, ?Tenant $tenant): bool
    {
        return true;
    }
}
