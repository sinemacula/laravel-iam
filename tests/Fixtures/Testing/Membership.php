<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Testing;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;

/**
 * A principal an identity holds beside itself, as a membership principal an
 * application keeps for each tenant a person belongs to: named by its own id,
 * owned by the identity given, and acting in the tenant of its own given, or in
 * none.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Membership implements Principal
{
    /**
     * Constructor.
     *
     * @param  string  $id
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     */
    public function __construct(

        /** The membership's own id. */
        public string $id,

        /** The identity that holds the membership. */
        private Identity $identity,

        /** The tenant of its own, or `null` when it acts in whichever the sign-in chooses. */
        private ?Tenant $tenant = null,
    ) {}

    /**
     * The membership's own id.
     *
     * @return string
     */
    #[\Override]
    public function getPrincipalIdentifier(): string
    {
        return $this->id;
    }

    /**
     * The identity that holds the membership.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     */
    #[\Override]
    public function getIdentity(): Identity
    {
        return $this->identity;
    }

    /**
     * The tenant of its own, or `null` when the membership acts in whichever
     * the sign-in chooses.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Tenant
     */
    #[\Override]
    public function getTenant(): ?Tenant
    {
        return $this->tenant;
    }
}
