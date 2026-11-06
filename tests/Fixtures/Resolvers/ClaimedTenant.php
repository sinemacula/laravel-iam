<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Resolvers;

use SineMacula\Laravel\Authentication\Contracts\Tenant;

/**
 * A tenant that is not the one a session records: the active tenant a trusted
 * bind, or a test, sets on the guard beside the session it validated.
 *
 * The context resolvers' tests set it to show that MFA's active tenant and an
 * event's tenant are the session's own, never one bound beside it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ClaimedTenant implements Tenant
{
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
}
