<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Authorization\Translation;

use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Tenancy\TenantReferences;

/**
 * Translates between opaque tenant ids and `laravel-authorization`'s tenant
 * references, refusing a tenant whose key is not exactly its identifier.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TenantTranslator
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Tenancy\TenantReferences  $tenants
     */
    public function __construct(

        /** Resolves a tenant id through `laravel-authentication`'s tenant resolver. */
        private TenantReferences $tenants,
    ) {}

    /**
     * `laravel-authorization`'s reference to the tenant the id names.
     *
     * @param  string  $tenantId
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    public function toReference(string $tenantId): Reference
    {
        $tenant = $this->tenants->tenant($tenantId);

        try {
            [$type, $key] = TenantScope::extractTenantPair($tenant);
        } catch (InvalidTenantException) {
            throw UnresolvedReferenceException::forTenant($tenantId);
        }

        return $key === $tenantId ? new Reference($type, $key) : throw UnresolvedReferenceException::forTenant($tenantId);
    }

    /**
     * The tenant id a reference names, once its key round-trips.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return string
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    public function idOf(Reference $tenant): string
    {
        return $this->toReference($tenant->id)->type === $tenant->type ? $tenant->id : throw UnresolvedReferenceException::forTenant($tenant->id);
    }
}
