<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Iam\Tenancy\Contracts\GrantScope;
use SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict;

/**
 * The grant scope while the authorization adapters are off: always `unknown`,
 * so the principal scope fails closed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class UnknownGrantScope implements GrantScope
{
    /**
     * Answer `unknown` for every identity and tenant.
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
