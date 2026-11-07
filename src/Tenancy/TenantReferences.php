<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;

/**
 * Resolves a tenant a member names by its opaque id to
 * `laravel-authentication`'s tenant, through `laravel-authentication`'s own
 * tenant resolver.
 *
 * SSO names a tenant only by its opaque id; `laravel-authentication` judges a
 * tenant's sessions by the tenant its resolver answers, matching each session's
 * active tenant against that tenant's identifier. So the id resolves to a
 * tenant only when the resolver answers one whose identifier is exactly that
 * id: one answered under another identifier would have the sessions of another
 * tenant judged, and those of this one left standing. A resolver that answers
 * no tenant (`laravel-authentication`'s default, `ResolveNoTenant`, answers
 * none for any id), or one of another identifier, throws
 * `UnresolvedReferenceException` (IAM-8.2), inside whatever transaction the
 * member opened, so the change it was making rolls back rather than leave the
 * tenant's sessions unjudged.
 *
 * The resolver is asked inside `WriteConnection::during()`, as
 * `laravel-authentication` asks it, so a model read the resolver makes is
 * pinned to the write connection, on whichever connection the tenant lives: a
 * replica that has not yet seen a new tenant, or a changed identifier, never
 * answers for it. The resolver is resolved from the container on every call, so
 * whatever the application binds, whenever it binds it, is the one asked, and
 * nothing is kept between calls (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TenantReferences
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Resolves `laravel-authentication`'s tenant resolver on every call. */
        private Container $container,
    ) {}

    /**
     * The tenant the id names.
     *
     * @param  string  $tenantId
     * @return \SineMacula\Laravel\Authentication\Contracts\Tenant
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    public function tenant(string $tenantId): Tenant
    {
        $resolver = $this->container->make(TenantResolver::class);
        $tenant   = WriteConnection::during($resolver, static fn (): ?Tenant => $resolver->resolve($tenantId));

        if ($tenant === null || IdentifierCoercion::stringify($tenant->getTenantIdentifier()) !== $tenantId) {
            throw UnresolvedReferenceException::forTenant($tenantId);
        }

        return $tenant;
    }
}
