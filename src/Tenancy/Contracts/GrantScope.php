<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy\Contracts;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict;

/**
 * The grant half of SSO's principal scope: whether an identity's grants stay
 * within a tenant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
interface GrantScope
{
    /**
     * Where the identity's grants stand against the tenant.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $tenantId
     * @return \SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict
     *
     * @throws \Throwable
     */
    public function judge(Identity $identity, string $tenantId): ScopeVerdict;
}
