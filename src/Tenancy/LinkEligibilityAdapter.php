<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy;

use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\Enums\LinkEligibilityVerdict;

/**
 * Answers SSO's link eligibility: only an accepted member of the connection's
 * tenant may link.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class LinkEligibilityAdapter implements LinkEligibility
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Tenancy\IdentityMemberships  $memberships
     */
    public function __construct(

        /** Reads the identity's memberships. */
        private IdentityMemberships $memberships,
    ) {}

    /**
     * Whether the identity accepted a membership of the connection's tenant.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return \SineMacula\Laravel\Sso\Linking\Enums\LinkEligibilityVerdict
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \LogicException
     * @throws \Throwable
     */
    #[\Override]
    public function judge(IdentityReference $identity, SsoConnection $connection): LinkEligibilityVerdict
    {
        $membership = $this->memberships->of($this->memberships->identity($identity))->in($connection->getTenantId());

        return $membership?->isAccepted() === true ? LinkEligibilityVerdict::ELIGIBLE : LinkEligibilityVerdict::INELIGIBLE;
    }
}
