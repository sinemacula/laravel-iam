<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Iam\Sso\IdentityReferences;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * Reads the current memberships of an identity SSO names by reference, from the
 * application's memberships (IAM-7.4), for the adapters that answer SSO's
 * tenant membership, link eligibility and principal scope.
 *
 * The reference resolves through the morph map (`IdentityReferences`), on the
 * write connection, and one that names nobody throws
 * `UnresolvedReferenceException` (IAM-8.2), inside whatever transaction SSO
 * opened, so the judgement fails rather than answer for nobody. The
 * application's memberships are asked inside `WriteConnection::during()` for
 * the identity, so a model read they make is pinned to the write connection, on
 * whichever connection the memberships live: a replica that has not yet seen a
 * membership accepted or revoked never answers for it, and the membership guard
 * they take as they answer is held in SSO's transaction, until it ends.
 * Whatever the memberships throw propagates. Stateless (IAM-8.1): the
 * memberships are resolved on every call.
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
     * The identity's current memberships, as the application answers them on
     * the write connection.
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
