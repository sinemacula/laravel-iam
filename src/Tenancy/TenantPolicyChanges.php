<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy;

use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Facades\Auth;

/**
 * Re-judges a tenant's sessions after its authentication policy changes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final readonly class TenantPolicyChanges
{
    /**
     * Re-judge the tenant's sessions and answer how many were revoked.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function changed(Tenant $tenant): int
    {
        return Auth::sessions()->tenantPolicyChanged($tenant);
    }
}
