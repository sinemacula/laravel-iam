<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Resolvers;

use Illuminate\Foundation\Auth\User;
use SineMacula\Laravel\Mfa\Concerns\HasFactors;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;

/**
 * An identity of MFA's that is no machine identity of
 * `laravel-authentication`'s, yet whose model says it may hold no factors, as
 * an application refuses factors to an identity of its own.
 *
 * It is never stored: the subject type adapter's tests read its class alone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Factorless extends User implements MultiFactorAuthenticatable
{
    use HasFactors;

    /**
     * Determine whether the identity may hold factors: it may not.
     *
     * @return bool
     */
    #[\Override]
    public function canHoldFactors(): bool
    {
        return false;
    }
}
