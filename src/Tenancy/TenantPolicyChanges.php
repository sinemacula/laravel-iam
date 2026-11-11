<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy;

use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Iam\Mfa\CurrentSession;

/**
 * Applies a change of a tenant's authentication policy to the sessions acting
 * in it through `laravel-authentication`'s `tenantPolicyChanged()` (IAM-4.5),
 * which judges them again once an enclosing transaction commits.
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
     * Judge the tenant's sessions against its policy as it now answers, and
     * answer how many were revoked.
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
