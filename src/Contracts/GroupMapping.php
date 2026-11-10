<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Contracts;

/**
 * The application's mapping of an identity provider's groups to grants
 * (IAM-7.2): which roles a person whose provider reports these groups, through
 * this connection, holds in the connection's tenant.
 *
 * SSO reports the groups a connection maps (its `groups` attribute) on every
 * verified result and changes nothing with them. With a mapping configured,
 * this package grants what it answers to a person provisioned through the
 * connection (`Provisioning\ProvisionOnUnlinkedResult`), and, where the
 * application opts in, again at each later sign-in (`Contracts\GroupResync`).
 * Each role it answers is granted to the new identity itself, in the
 * connection's tenant (`Provisioning\GrantInstruction`): a connection's groups
 * never grant anything beyond its own tenant, since they are only as
 * trustworthy as the connection, which the tenant's own administrator may
 * control.
 *
 * Answer from the values given alone, and the same for the same values: it is
 * asked inside the provisioning listener's transaction, after SSO's locks, so
 * read nothing that takes a lock, and write nothing. Groups are compared byte
 * for byte, as the provider sent them. Answer no instruction for a group it
 * does not map; answer none at all to grant nothing. Throw to refuse: the
 * provisioning, or the sign-in, then rolls back.
 *
 * Name the implementation in `iam.provisioning.groups.mapping`, or bind it in
 * the container; with neither, `iam.provisioning.groups.map` is the mapping
 * (`Provisioning\ConfiguredGroupMapping`), and with that empty too, groups map
 * to nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
interface GroupMapping
{
    /**
     * The roles a person reported in the groups, through the connection, holds
     * in the connection's tenant.
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
