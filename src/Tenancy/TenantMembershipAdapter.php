<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy;

use SineMacula\Laravel\Sso\Contracts\TenantMembership;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\MembershipStanding;

/**
 * SSO's tenant membership, answered from the application's memberships
 * (IAM-7.4, SSO-8.8): the identity's current membership of exactly the tenant
 * asked, byte for byte, and when the person accepted it.
 *
 * SSO counts it for linking by a verified domain only when the person accepted
 * it strictly before the domain's current verification. So only a membership
 * the person accepted is a standing: one the person has not accepted (an
 * invitation, a membership an administrator created) is none, and so is no
 * membership of the tenant. A membership the set holds is held whether the set
 * is complete or not, so an incomplete set answers for the memberships it
 * holds; it never makes one up. The application's answer is the person's
 * acceptance time, never an administrator's, by its contract.
 *
 * SSO asks it at a completion and again inside the redemption's transaction,
 * under its locks. The identity resolves through the morph map and the
 * memberships are read on the write connection (`IdentityMemberships`); an
 * identity that cannot be resolved throws `UnresolvedReferenceException` inside
 * SSO's transaction (IAM-8.2), and whatever the memberships throw propagates.
 * It takes no lock of its own: SSO's contract requires the answer to stay true
 * until the redeemer's transaction commits, which the application's memberships
 * guarantee by taking their membership guard as they answer, held until SSO's
 * transaction ends, the guard every writer that revokes a membership takes too
 * (`Contracts\Memberships`); SSO asks only under its own locks, so the guard
 * comes after them. Stateless (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TenantMembershipAdapter implements TenantMembership
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
     * The identity's current membership of the tenant, accepted by the person
     * at the time it was, or none.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $tenantId
     * @return \SineMacula\Laravel\Sso\Linking\MembershipStanding
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \LogicException
     * @throws \Throwable
     */
    #[\Override]
    public function standing(IdentityReference $identity, string $tenantId): MembershipStanding
    {
        $acceptedAt = $this->memberships->of($this->memberships->identity($identity))->in($tenantId)?->acceptedAt;

        return $acceptedAt === null ? MembershipStanding::none() : MembershipStanding::accepted($acceptedAt);
    }
}
