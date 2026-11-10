<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Authorization;

use SineMacula\Laravel\Authentication\Contracts\Tenant;

/**
 * A tenant of `laravel-authentication`'s that `laravel-authorization` cannot
 * scope to: it names itself by its identifier, and is neither a model nor one
 * of `laravel-authorization`'s tenants.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class UnscopedTenant implements Tenant
{
    /**
     * Constructor.
     *
     * @param  string  $id
     */
    public function __construct(

        /** The tenant's identifier. */
        private string $id,
    ) {}

    /**
     * The tenant's identifier.
     *
     * @return string
     */
    #[\Override]
    public function getTenantIdentifier(): string
    {
        return $this->id;
    }
}
