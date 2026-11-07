<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy;

use Carbon\CarbonImmutable;

/**
 * One of an identity's current memberships, as the application's membership
 * contract answers it (IAM-7.4): the tenant it is a membership of, `null` for a
 * platform principal, which belongs to no tenant and so reaches beyond every
 * one, and when the person accepted it.
 *
 * The acceptance time is the person's, never an administrator's: a membership
 * an administrator created, or an invitation the person has not taken up, has
 * none. SSO counts a membership for linking by a verified domain only when the
 * person accepted it strictly before the domain's current verification, so a
 * tenant that claims a domain cannot add people and then capture them; a
 * creation time standing in for an acceptance would let it. A tenant id is the
 * application's opaque id, compared byte for byte, never blank.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final readonly class Membership
{
    /**
     * Constructor.
     *
     * @param  ?string  $tenantId
     * @param  ?\Carbon\CarbonImmutable  $acceptedAt
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The tenant it is a membership of, or `null` for a platform principal. */
        public ?string $tenantId,

        /** When the person accepted it, or `null` when the person has not. */
        public ?CarbonImmutable $acceptedAt = null,
    ) {
        if ($tenantId !== null && trim($tenantId) === '') {
            throw new \InvalidArgumentException('A membership names its tenant by a non-blank id, or names none for a platform principal.');
        }
    }

    /**
     * A membership of the tenant, accepted by the person at the time given, or
     * not accepted yet.
     *
     * @param  string  $tenantId
     * @param  ?\Carbon\CarbonImmutable  $acceptedAt
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function of(string $tenantId, ?CarbonImmutable $acceptedAt = null): self
    {
        return new self($tenantId, $acceptedAt);
    }

    /**
     * A platform principal, which belongs to no tenant, accepted by the person
     * at the time given, or not accepted yet.
     *
     * @param  ?\Carbon\CarbonImmutable  $acceptedAt
     * @return self
     */
    public static function platform(?CarbonImmutable $acceptedAt = null): self
    {
        return new self(null, $acceptedAt);
    }

    /**
     * Whether it is a platform principal, of no tenant.
     *
     * @return bool
     */
    public function isPlatform(): bool
    {
        return $this->tenantId === null;
    }

    /**
     * Whether it is a membership of exactly the tenant given, byte for byte.
     *
     * @param  string  $tenantId
     * @return bool
     */
    public function isOf(string $tenantId): bool
    {
        return $this->tenantId === $tenantId;
    }

    /**
     * Whether the person has accepted it.
     *
     * @return bool
     */
    public function isAccepted(): bool
    {
        return $this->acceptedAt !== null;
    }
}
