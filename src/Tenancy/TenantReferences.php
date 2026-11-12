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
 * Resolves a tenant id through `laravel-authentication`'s tenant resolver on
 * the write connection, refusing a tenant answered under another identifier.
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
