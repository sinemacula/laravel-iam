<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use SineMacula\Laravel\Authentication\Admission\ActivationPolicy;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Mfa\Contracts\ActiveStateResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;

/**
 * MFA's active state, read through `laravel-authentication`'s activation
 * policy, which reads the primary.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ActiveStateResolverAdapter implements ActiveStateResolver
{
    /**
     * Whether the identity is active, else as `isMfaActive()` says.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return bool
     */
    #[\Override]
    public function isActive(MultiFactorAuthenticatable $identity): bool
    {
        return $identity instanceof CanBeActive ? ActivationPolicy::isActive($identity) : $identity->isMfaActive();
    }
}
