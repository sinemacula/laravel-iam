<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Mfa;

use SineMacula\Laravel\Mfa\Contracts\IdentityRequirement;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * An identity requirement that asks nothing of anyone, so a session judged
 * again after a factor is enrolled or removed stays active and can be stepped
 * up with that factor at once.
 *
 * The end-to-end tests bind it, with the MFA application's own requirement set
 * to `never`, where they follow a factor from its enrolment to its use.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RequiresNothing implements IdentityRequirement
{
    /**
     * Ask nothing of the identity.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return \SineMacula\Laravel\Mfa\Requirements\Requirement
     */
    #[\Override]
    public function requirementFor(MultiFactorAuthenticatable $identity, string $application): Requirement
    {
        return Requirement::none();
    }
}
