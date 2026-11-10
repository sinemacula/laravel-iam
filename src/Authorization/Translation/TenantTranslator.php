<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Authorization\Translation;

use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Tenancy\TenantReferences;

/**
 * Translates between the opaque tenant ids SSO, `laravel-authentication` and
 * this package's tenancy contracts name a tenant by, and
 * `laravel-authorization`'s `Reference` to a tenant, its morph type and key.
 *
 * A tenant id names a tenant to `laravel-authorization` (`toReference()`) by
 * the tenant `laravel-authentication`'s tenant resolver answers for it
 * (`Tenancy\TenantReferences`, which answers only a tenant whose identifier is
 * exactly that id, on the write connection), read as `laravel-authorization`
 * reads a tenant (`TenantScope::extractTenantPair()`): its morph class and its
 * key, as a string. The key must be the id itself, byte for byte, as
 * `laravel-authentication` records a session's tenant by its identifier and
 * `laravel-authorization` keys a grant by the tenant's key, so the two name one
 * tenant alike (the requirement checker equates them the same way,
 * `RequirementCheckerAdapter`). A tenant the resolver does not answer, one that
 * is neither an Eloquent model nor `laravel-authorization`'s
 * `AuthorizableTenant`, and one whose key is not exactly its identifier, throw
 * `UnresolvedReferenceException` (IAM-8.2), inside whatever transaction is
 * open, so the change being made rolls back rather than name another tenant, or
 * none.
 *
 * The other way (`idOf()`), a `Reference` names the tenant by its key, which is
 * that same identifier, but only once the round trip holds: the key, resolved
 * as an id, must name a tenant whose morph class is the reference's type and
 * whose key is the reference's key. Taking the key on trust would let a tenant
 * whose key happens to be another tenant's identifier be read as that other
 * tenant, which, handed to SSO's scope widening, would spare the other tenant's
 * links from suspension, and, handed to the tree, would place a grant in the
 * wrong part of it. One that does not round-trip throws
 * `UnresolvedReferenceException`, as `toReference()` does.
 *
 * It keeps nothing between calls (IAM-8.1).
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
     * The tenant id a reference names: its key, once the key resolved as an id
     * names the tenant the reference does, by type and key.
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
