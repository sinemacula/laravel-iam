<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Iam\Tenancy\Contracts\GrantScope;
use SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict;

/**
 * The grant half of SSO's principal scope until `laravel-authorization` ships
 * its grant scope query (AUTHZ-14.2, M11): `unknown` for every identity and
 * tenant, so the principal scope never answers `within_tenant` on the
 * memberships alone (fail closed; Q9). It reads nothing and keeps nothing, so
 * it is shared.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class UnknownGrantScope implements GrantScope
{
    /**
     * `unknown`: nothing can tell where the identity's grants reach yet.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $tenantId
     * @return \SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict
     */
    #[\Override]
    public function judge(Identity $identity, string $tenantId): ScopeVerdict
    {
        return ScopeVerdict::UNKNOWN;
    }
}
