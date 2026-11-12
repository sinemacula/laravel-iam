<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver;

/**
 * MFA's subject type: a `laravel-authentication` machine identity is never a
 * person.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SubjectTypeResolverAdapter implements SubjectTypeResolver
{
    /**
     * Whether the identity is a person MFA may hold factors for.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return bool
     */
    #[\Override]
    public function isPerson(Authenticatable $identity): bool
    {
        return !$identity instanceof MachineIdentity
            && $identity instanceof MultiFactorAuthenticatable
            && $identity->canHoldFactors();
    }
}
