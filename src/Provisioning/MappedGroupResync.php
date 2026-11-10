<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Provisioning;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Iam\Contracts\GroupResync;
use SineMacula\Laravel\Iam\Exceptions\GroupMappingMisconfiguredException;

/**
 * The re-sync this package ships for the application to opt into (IAM-7.2): at
 * each later sign-in, the identity's own roles in the connection's tenant
 * become exactly those the group mapping now answers for the groups the
 * provider reports, so a group added at the provider grants its roles, and a
 * group removed there revokes them.
 *
 * Name it in `iam.provisioning.groups.resync`. It grants and revokes only the
 * roles of the identity itself in the connection's tenant
 * (`GroupGrants::sync()`): a role an administrator granted the identity there
 * is revoked too, unless the mapping answers it, while a role of the identity's
 * principals, of another tenant or platform-wide is never touched; grant an
 * administrator's roles to the principal, or implement `Contracts\GroupResync`
 * to keep them. It never grants a role the mapping does not answer. A
 * connection that reports no groups at all revokes every role the groups gave.
 * With no mapping configured it throws `GroupMappingMisconfiguredException`,
 * refusing the sign-in, rather than revoke every role for want of one. It keeps
 * nothing between calls (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final readonly class MappedGroupResync implements GroupResync
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Provisioning\GroupSettings  $settings
     * @param  \SineMacula\Laravel\Iam\Provisioning\GroupGrants  $grants
     */
    public function __construct(

        /** Finds the application's group mapping. */
        private GroupSettings $settings,

        /** Makes the identity's roles in the tenant the mapping's. */
        private GroupGrants $grants,
    ) {}

    /**
     * Make the identity's own roles in the connection's tenant those the
     * mapping answers for the groups.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $connectionId
     * @param  string  $tenantId
     * @param  list<string>  $groups
     * @return void
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\GroupMappingMisconfiguredException
     */
    #[\Override]
    public function resync(Identity $identity, string $connectionId, string $tenantId, array $groups): void
    {
        $mapping = $this->settings->mapping() ?? throw GroupMappingMisconfiguredException::forNoMapping(GroupSettings::MAPPING);

        $this->grants->sync($identity, $tenantId, $mapping->grantsFor($connectionId, $tenantId, $groups));
    }
}
