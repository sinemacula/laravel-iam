<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Contracts;

/**
 * Maps an identity provider's groups to the roles a person holds in the
 * connection's tenant, never beyond it, since the tenant's administrator may
 * control the connection.
 *
 * Answered inside the provisioning transaction, after SSO's locks: read nothing
 * that locks, write nothing, and answer the same for the same values. Throw to
 * refuse. With none bound, `iam.provisioning.groups.map` is used.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
interface GroupMapping
{
    /**
     * The roles the groups grant in the connection's tenant.
     *
     * @param  string  $connectionId
     * @param  string  $tenantId
     * @param  list<string>  $groups
     * @return list<\SineMacula\Laravel\Iam\Provisioning\GrantInstruction>
     *
     * @throws \Throwable
     */
    public function grantsFor(string $connectionId, string $tenantId, array $groups): array;
}
