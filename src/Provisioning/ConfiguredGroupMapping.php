<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Provisioning;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Iam\Contracts\GroupMapping;

/**
 * The group mapping read from `iam.provisioning.groups.map` (IAM-7.2): each
 * group name to a role's name or a list of them, granted in the connection's
 * tenant alone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ConfiguredGroupMapping implements GroupMapping
{
    /** @var string Why a malformed map is refused. */
    private const string MALFORMED = GroupSettings::MAP . ' must map each non-empty group name to a role\'s name or a list of them.';

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
     * @throws \LogicException
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
     * @throws \LogicException
     */
    private function map(): array
    {
        $map = $this->config->get(GroupSettings::MAP);

        if (!is_array($map) || ($map !== [] && array_is_list($map))) {
            throw new \LogicException(self::MALFORMED);
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
     * @throws \LogicException
     */
    private static function rolesOf(int|string $group, mixed $named): array
    {
        $listed = is_string($named) ? [$named] : $named;

        return $group !== '' && is_array($listed) && array_is_list($listed) && self::areRoles($listed)
            ? $listed
            : throw new \LogicException(self::MALFORMED);
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
