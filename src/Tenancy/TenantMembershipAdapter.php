<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy;

use SineMacula\Laravel\Sso\Contracts\TenantMembership;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\MembershipStanding;

/**
 * Answers SSO's tenant membership: the identity's accepted membership of the
 * tenant and when the person accepted it.
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
     * The identity's accepted membership of the tenant, or none.
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
