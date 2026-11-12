<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy;

use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Iam\Mfa\CurrentSession;

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
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Mfa\CurrentSession  $sessions
     */
    public function __construct(

        /** Resolves the session service the change goes through. */
        private CurrentSession $sessions,
    ) {}

    /**
     * Re-judge the tenant's sessions and answer how many were revoked.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \Throwable
     */
    public function changed(Tenant $tenant): int
    {
        return $this->sessions->identitySessions()->tenantPolicyChanged($tenant);
    }
}
