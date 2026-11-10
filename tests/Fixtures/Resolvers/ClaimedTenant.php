<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Resolvers;

use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant;

/**
 * A tenant that is not the one a session records: the active tenant a trusted
 * bind, or a test, sets on the guard beside the session it validated.
 *
 * The context resolvers' tests set it to show that MFA's active tenant and an
 * event's tenant are the session's own, never one bound beside it.
 *
 * It is `laravel-authorization`'s tenant too, named by its morph type and that
 * same id, so a tree change reported for it reaches `laravel-authorization`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ClaimedTenant implements AuthorizableTenant, Tenant
{
    /** @var string The morph type `laravel-authorization` names a claimed tenant by. */
    public const string TYPE = 'claimed-tenant';

    /**
     * Constructor.
     *
     * @param  string  $id
     */
    public function __construct(

        /** The tenant's opaque id. */
        private string $id,
    ) {}

    /**
     * The tenant's opaque id.
     *
     * @return string
     */
    #[\Override]
    public function getTenantIdentifier(): string
    {
        return $this->id;
    }

    /**
     * The tenant's opaque id, as `laravel-authorization` keys its grants.
     *
     * @return string
     */
    #[\Override]
    public function getKey(): string
    {
        return $this->id;
    }

    /**
     * The morph type `laravel-authorization` names a claimed tenant by.
     *
     * @return string
     */
    #[\Override]
    public function getMorphClass(): string
    {
        return self::TYPE;
    }
}
