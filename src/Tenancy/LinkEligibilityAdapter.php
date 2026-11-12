<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy;

use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\Enums\LinkEligibilityVerdict;

/**
 * SSO's link eligibility, answered from the application's memberships (IAM-7.4,
 * SSO-8.5): an identity may link through a connection only as a member of the
 * connection's tenant, by a membership the person has accepted.
 *
 * A `link` is the person's own act, through their own session, so it makes them
 * reachable through the tenant's provider: an invitation not taken up, or a
 * membership an administrator created and the person never accepted, does not
 * make them eligible, and nor does a membership of any other tenant or a
 * platform principal. The membership is the connection's tenant's exactly, byte
 * for byte. A membership the set holds is held whether the set is complete or
 * not, so an incomplete set answers for the memberships it holds.
 *
 * SSO asks it at a `link` flow's completion and again inside its redemption's
 * transaction, under its locks. The identity resolves through the morph map and
 * the memberships are read on the write connection (`IdentityMemberships`); an
 * identity that cannot be resolved throws `UnresolvedReferenceException` inside
 * SSO's transaction (IAM-8.2), and whatever the memberships throw propagates.
 * It takes no lock of its own: the application's memberships take their
 * membership guard as they answer, held until SSO's transaction ends, and every
 * writer that revokes a membership takes it too (`Contracts\Memberships`), so a
 * revocation waits for the `link` redemption that read the membership to
 * commit; SSO asks only under its own locks, so the guard comes after them.
 * Stateless (IAM-8.1).
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
     * Whether the identity may link through the connection: only as a member,
     * by acceptance, of the connection's tenant.
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
