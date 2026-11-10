<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Provisioning;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Iam\Contracts\GroupMapping;
use SineMacula\Laravel\Iam\Exceptions\GroupMappingMisconfiguredException;

/**
 * The group mapping read from configuration (IAM-7.2):
 * `iam.provisioning.groups.map` maps each group name, as a provider reports it,
 * to the name of a role or a list of them, and every connection's groups are
 * mapped by it alike, each role granted in the connection's tenant alone
 * (`GrantInstruction::role()`).
 *
 * ```php
 * 'groups' => [
 *     'map' => [
 *         'finance'     => 'invoices.viewer',
 *         'finance-ops' => ['invoices.viewer', 'invoices.approver'],
 *     ],
 * ],
 * ```
 *
 * Groups are compared byte for byte, and a group the map does not name maps to
 * nothing. Each role is answered once, in the order the groups first name it. A
 * map that is no array, a list rather than a map, or one that holds an empty
 * group name, or a role that is no non-empty string, throws
 * `GroupMappingMisconfiguredException` when it is read, inside the transaction
 * asking it, rather than map those groups to nothing. The map is read on every
 * call, and nothing is kept between calls (IAM-8.1). A mapping that tells one
 * connection's groups from another's, or grants a role across the tenant's
 * subtree, is the application's own `Contracts\GroupMapping`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ConfiguredGroupMapping implements GroupMapping
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** The configuration holding the map. */
        private Repository $config,
    ) {}

    /**
     * The roles the map gives the groups, each in the connection's tenant.
     *
     * @param  string  $connectionId
     * @param  string  $tenantId
     * @param  list<string>  $groups
     * @return list<\SineMacula\Laravel\Iam\Provisioning\GrantInstruction>
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\GroupMappingMisconfiguredException
     */
    #[\Override]
    public function grantsFor(string $connectionId, string $tenantId, array $groups): array
    {
        $map   = $this->map();
        $roles = [];

        foreach ($groups as $group) {
            $roles = [...$roles, ...$map[$group] ?? []];
        }

        return array_map(GrantInstruction::role(...), array_values(array_unique($roles)));
    }

    /**
     * The map, each group to its list of roles, refused unless every group and
     * every role is a non-empty string.
     *
     * @return array<array-key, list<string>>
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\GroupMappingMisconfiguredException
     */
    private function map(): array
    {
        $map = $this->config->get(GroupSettings::MAP);

        if (!is_array($map) || ($map !== [] && array_is_list($map))) {
            throw GroupMappingMisconfiguredException::forMap(GroupSettings::MAP);
        }

        $roles = [];

        foreach ($map as $group => $named) {
            $roles[$group] = self::rolesOf($group, $named);
        }

        return $roles;
    }

    /**
     * The roles the map names for the group: a role's name, or a list of them,
     * refused unless the group is named and every role is a non-empty string.
     *
     * @param  array-key  $group
     * @param  mixed  $named
     * @return list<string>
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\GroupMappingMisconfiguredException
     */
    private static function rolesOf(int|string $group, mixed $named): array
    {
        $listed = is_string($named) ? [$named] : $named;

        return $group !== '' && is_array($listed) && array_is_list($listed) && self::areRoles($listed)
            ? $listed
            : throw GroupMappingMisconfiguredException::forMap(GroupSettings::MAP);
    }

    /**
     * Whether every value is a role's name: a string with something besides
     * whitespace in it.
     *
     * @param  list<mixed>  $listed
     * @return bool
     *
     * @phpstan-assert-if-true list<string> $listed
     */
    private static function areRoles(array $listed): bool
    {
        foreach ($listed as $role) {
            if (!is_string($role) || trim($role) === '') {
                return false;
            }
        }

        return true;
    }
}
