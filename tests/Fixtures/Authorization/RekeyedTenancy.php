<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Authorization;

use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;

/**
 * A tenant resolver over organisations keyed otherwise than by their
 * identifiers, as an application whose tenants have integer keys and
 * identifiers taken from another column has them: each identifier it knows
 * resolves to the organisation holding the key it maps to, and any other to
 * none.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RekeyedTenancy implements TenantResolver
{
    /**
     * Constructor.
     *
     * @param  array<array-key, string>  $keys
     */
    public function __construct(

        /** The key of each organisation, by its identifier. */
        private array $keys,
    ) {}

    /**
     * The organisation the identifier names, keyed as the map keys it, or none.
     *
     * @param  string  $tenantId
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Tenant
     */
    #[\Override]
    public function resolve(string $tenantId): ?Tenant
    {
        return isset($this->keys[$tenantId]) ? new RekeyedOrganisation($this->keys[$tenantId], $tenantId) : null;
    }
}
