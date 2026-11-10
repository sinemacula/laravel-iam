<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Authorization;

use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;

/**
 * A tenancy of two tenant types: an id beginning `account-` resolves to the
 * account of that id, and every other id to the organisation of that id.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AccountTenancy implements TenantResolver
{
    /**
     * The account or the organisation of the id.
     *
     * @param  string  $tenantId
     * @return \SineMacula\Laravel\Authentication\Contracts\Tenant
     */
    #[\Override]
    public function resolve(string $tenantId): Tenant
    {
        return str_starts_with($tenantId, Account::PREFIX) ? new Account($tenantId) : new Organisation($tenantId);
    }
}
