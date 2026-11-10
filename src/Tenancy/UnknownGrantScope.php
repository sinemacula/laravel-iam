<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Iam\Tenancy\Contracts\GrantScope;
use SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict;

/**
 * The grant half of SSO's principal scope while the authorization
 * capability's switch (`iam.adapters.authorization`) is off, and this package
 * answers no grant from `laravel-authorization`'s grant scope query
 * (`Authorization\GrantScopeAdapter`): `unknown` for every identity and
 * tenant, so the principal scope never answers `within_tenant` on the
 * memberships alone (fail closed; Q9). An application that binds the
 * authorization seams itself binds its own grant half too. It reads nothing and
 * keeps nothing, so it is shared.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class UnknownGrantScope implements GrantScope
{
    /**
     * `unknown`: nothing here can tell where the identity's grants reach.
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
