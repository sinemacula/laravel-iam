<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Sso;

use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\Enums\LinkEligibilityVerdict;

/**
 * A stand-in for the application's link eligibility, which this package answers
 * from the membership contract only from IAM-7.4: every identity may link
 * through every connection. SSO's default refuses every identity, so no `link`
 * flow starts until one is bound.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class EveryoneMayLink implements LinkEligibility
{
    /**
     * Let the identity link.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return \SineMacula\Laravel\Sso\Linking\Enums\LinkEligibilityVerdict
     */
    #[\Override]
    public function judge(IdentityReference $identity, SsoConnection $connection): LinkEligibilityVerdict
    {
        unset($identity, $connection);

        return LinkEligibilityVerdict::ELIGIBLE;
    }
}
