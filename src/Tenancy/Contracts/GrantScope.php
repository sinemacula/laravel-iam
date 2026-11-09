<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy\Contracts;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict;

/**
 * The grant half of SSO's principal scope (IAM-6.8): whether every grant an
 * identity holds stays within a tenant, `outside_tenant` when one reaches
 * beyond it (a grant on another tenant, or on the platform), and `unknown` when
 * it cannot be told.
 *
 * It is to be answered by `laravel-authorization`'s grant scope query
 * (AUTHZ-14.2), which this package binds with the second part of M11, so it is
 * bound to `UnknownGrantScope` until then: SSO's principal scope answers
 * `within_tenant` for nobody, and linking by a verified domain stays refused.
 * It is this package's own port, not a member's seam, so it is bound only while
 * unbound, and an application or a test binding of its own is kept. It reads
 * the write connection, keeps nothing of one call for the next, takes no lock,
 * and lets an error propagate.
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
