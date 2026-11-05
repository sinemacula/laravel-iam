<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Mfa\Pending;

use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;

/**
 * An additional-factor policy that asks every sign-in for an additional
 * verification, of any age, so a password alone leaves the session pending.
 *
 * It stands in for the requirement MFA would set, so the tests of the pending
 * adapters arrange pending sessions without the requirement adapters.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RequiresAdditionalVerification implements AdditionalFactorPolicy
{
    /**
     * An additional verification, of any age.
     *
     * @param  \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext  $context
     * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
     */
    #[\Override]
    public function requirementFor(AdditionalFactorContext $context): Requirement
    {
        return new Requirement(new RequirementPart);
    }
}
