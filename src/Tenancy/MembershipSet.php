<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy;

/**
 * An identity's current memberships, marked incomplete when the application
 * could not read them all.
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
        // A tenant id is never blank, so '' is the platform principal's key.
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
     * The memberships the application could read, which may not be all.
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
     * The membership of exactly the tenant given, or `null`.
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
     * Whether the set holds a platform principal or another tenant.
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
