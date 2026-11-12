<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Iam\Sso\IdentityReferences;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * Reads the application's memberships of an identity SSO names, on the write
 * connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class IdentityMemberships
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Sso\IdentityReferences  $identities
     * @param  \SineMacula\Laravel\Iam\Tenancy\TenancyContracts  $contracts
     */
    public function __construct(

        /** Resolves the identity SSO names. */
        private IdentityReferences $identities,

        /** Finds the application's memberships on every call. */
        private TenancyContracts $contracts,
    ) {}

    /**
     * The identity the reference names.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $reference
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    public function identity(IdentityReference $reference): Identity
    {
        return $this->identities->identity($reference);
    }

    /**
     * The identity's current memberships, read on the write connection.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return \SineMacula\Laravel\Iam\Tenancy\MembershipSet
     *
     * @throws \LogicException
     * @throws \Throwable
     */
    public function of(Identity $identity): MembershipSet
    {
        $memberships = $this->contracts->memberships();

        return WriteConnection::during($identity, static fn (): MembershipSet => $memberships->of($identity));
    }
}
