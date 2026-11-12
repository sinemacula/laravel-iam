<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Provisioning;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Iam\Contracts\GroupMapping;
use SineMacula\Laravel\Iam\Contracts\GroupResync;

/**
 * Makes an identity's roles in the connection's tenant exactly those the group
 * mapping answers, revoking any other.
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
     * Sync the identity's roles in the tenant to the mapping's.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $connectionId
     * @param  string  $tenantId
     * @param  list<string>  $groups
     * @return void
     *
     * @throws \LogicException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    public function resync(Identity $identity, string $connectionId, string $tenantId, array $groups): void
    {
        $message = '%s is unbound and %s maps no group; a re-sync without a mapping would revoke every role.';
        $mapping = $this->settings->mapping() ?? throw new \LogicException(sprintf($message, GroupMapping::class, GroupSettings::MAP));

        $this->grants->sync($identity, $tenantId, $mapping->grantsFor($connectionId, $tenantId, $groups));
    }
}
