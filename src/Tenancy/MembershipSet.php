<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy;

/**
 * An identity's current memberships, as the application's membership contract
 * answers them (IAM-7.4): complete, or marked incomplete when the application
 * could not read every one of them.
 *
 * A set holds at most one membership of each tenant, and at most one platform
 * principal: an application that keeps several principals of one tenant answers
 * the one membership they make up, accepted when the person first accepted any
 * of them. Completeness is what lets a set say what the identity does not hold:
 * a membership a set holds is held whether it is complete or not, but only a
 * complete set says the identity holds nothing beyond it, so only a complete
 * one can place the identity within a tenant, and an incomplete one never
 * places it outside one either (`PrincipalScopeAdapter`): SSO takes a set the
 * application could not read completely as `unknown`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final readonly class MembershipSet
{
    /**
     * Constructor.
     *
     * @param  list<\SineMacula\Laravel\Iam\Tenancy\Membership>  $memberships
     * @param  bool  $complete
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The memberships, each tenant's once. */
        public array $memberships,

        /** Whether these are every one of the identity's current memberships. */
        public bool $complete = true,
    ) {
        // A tenant's id is never blank, so the blank key is a platform
        // principal's alone.
        $keys = array_map(static fn (Membership $membership): string => $membership->tenantId ?? '', $memberships);

        if (count(array_unique($keys)) !== count($keys)) {
            throw new \InvalidArgumentException('A membership set holds each tenant\'s membership, and a platform principal, once.');
        }
    }

    /**
     * Every one of the identity's current memberships.
     *
     * @param  \SineMacula\Laravel\Iam\Tenancy\Membership  ...$memberships
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function complete(Membership ...$memberships): self
    {
        return new self(array_values($memberships));
    }

    /**
     * Those of the identity's current memberships the application could read,
     * which may not be every one.
     *
     * @param  \SineMacula\Laravel\Iam\Tenancy\Membership  ...$memberships
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function incomplete(Membership ...$memberships): self
    {
        return new self(array_values($memberships), false);
    }

    /**
     * The membership of exactly the tenant given, byte for byte, or `null` when
     * the set holds none.
     *
     * @param  string  $tenantId
     * @return ?\SineMacula\Laravel\Iam\Tenancy\Membership
     */
    public function in(string $tenantId): ?Membership
    {
        foreach ($this->memberships as $membership) {
            if ($membership->isOf($tenantId)) {
                return $membership;
            }
        }

        return null;
    }

    /**
     * Whether the set holds a membership that reaches beyond the tenant given:
     * a platform principal, or a membership of any other tenant.
     *
     * @param  string  $tenantId
     * @return bool
     */
    public function reachesBeyond(string $tenantId): bool
    {
        foreach ($this->memberships as $membership) {
            if (!$membership->isOf($tenantId)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether these are every one of the identity's current memberships.
     *
     * @return bool
     */
    public function isComplete(): bool
    {
        return $this->complete;
    }
}
