<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Resolvers;

use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;

/**
 * A tenancy in which every tenant identifier names an active tenant, and every
 * principal may act in every tenant, so a session a test records in a tenant
 * stays admitted by `laravel-authentication` on every later judgement (a
 * reauthentication, a step-up, a factor change).
 *
 * The end-to-end tests bind it as `laravel-authentication`'s tenant resolver
 * and tenant access, so the tenant MFA's events and requirements read is the
 * one the validated session records, from a sign-in that
 * `laravel-authentication` goes on admitting.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class OpenTenancy implements TenantAccess, TenantResolver
{
    /**
     * Resolve the identifier to a tenant of that identifier.
     *
     * @param  string  $tenantId
     * @return \SineMacula\Laravel\Authentication\Contracts\Tenant
     */
    #[\Override]
    public function resolve(string $tenantId): Tenant
    {
        return new ClaimedTenant($tenantId);
    }

    /**
     * Let the principal act in the tenant.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return bool
     */
    #[\Override]
    public function mayActIn(Principal $principal, ?Tenant $tenant): bool
    {
        return true;
    }
}
