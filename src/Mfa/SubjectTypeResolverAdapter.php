<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver;

/**
 * MFA's subject type, read from `laravel-authentication`'s machine identity
 * contract (IAM-3.12): an identity whose class declares `MachineIdentity` (an
 * API client or a service account) is a machine, never a person, whatever its
 * model says of the factors it may hold, so every MFA operation refuses it as
 * one.
 *
 * Any other identity is judged as MFA judges it alone: a person only when it is
 * MFA's identity (`MultiFactorAuthenticatable`) and says it may hold factors,
 * so an application's own refusal of factors to an identity still stands, and
 * an identity of another kind is never taken for a person.
 *
 * It reads the identity's class and nothing else: no query, no request and no
 * state between calls (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SubjectTypeResolverAdapter implements SubjectTypeResolver
{
    /**
     * Whether the identity is a person: no machine identity, and an identity
     * MFA may hold factors for.
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
