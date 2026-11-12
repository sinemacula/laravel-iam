<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy;

use Carbon\CarbonImmutable;

/**
 * One of an identity's memberships: its tenant (`null` for a platform
 * principal) and when the person, never an administrator, accepted it.
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
     * A membership of the tenant.
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
     * A platform principal, which belongs to no tenant.
     *
     * @param  ?\Carbon\CarbonImmutable  $acceptedAt
     * @return self
     */
    public static function platform(?CarbonImmutable $acceptedAt = null): self
    {
        return new self(null, $acceptedAt);
    }

    /**
     * Whether it is a platform principal.
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
