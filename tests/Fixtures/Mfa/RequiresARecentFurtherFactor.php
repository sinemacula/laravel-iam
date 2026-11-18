<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Mfa;

use SineMacula\Laravel\Mfa\Contracts\IdentityRequirement;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * An identity requirement that asks anyone holding a factor for a recent one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RequiresARecentFurtherFactor implements IdentityRequirement
{
    /**
     * Create a requirement for a further factor made within the age given.
     *
     * @param  int  $maxAge
     */
    public function __construct(

        /** How old the further factor may be, in seconds. */
        private int $maxAge,
    ) {}

    /**
     * Ask an identity holding a factor for a recent further factor.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return \SineMacula\Laravel\Mfa\Requirements\Requirement
     */
    #[\Override]
    public function requirementFor(MultiFactorAuthenticatable $identity, string $application): Requirement
    {
        return $identity->isMfaEnabled() ? Requirement::none()->withAdditionalVerification($this->maxAge) : Requirement::none();
    }
}
