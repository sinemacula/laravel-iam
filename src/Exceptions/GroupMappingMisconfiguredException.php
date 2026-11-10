<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Exceptions;

use SineMacula\Laravel\Iam\Bindings\Contracts\ReportsMisconfiguration;

/**
 * Thrown when the application's group mapping or group re-sync cannot be built
 * or read (IAM-7.2): `iam.provisioning.groups.mapping` or
 * `iam.provisioning.groups.resync` names what is no class implementing its
 * contract, or holds a value that is no class name at all, the container
 * binding either is resolved by resolves to what is no such implementation,
 * `iam.provisioning.groups.map` is no map of group names to role names, or a
 * re-sync that grants from the mapping finds none.
 *
 * It is thrown where the groups would be mapped, inside the provisioning or the
 * sign-in's transaction, so that transaction rolls back rather than proceed as
 * though the groups mapped to nothing, which a re-sync would take as a reason
 * to revoke. The message names the configuration key or the binding, never a
 * group, a role, a result or an identity.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final class GroupMappingMisconfiguredException extends \LogicException implements ReportsMisconfiguration
{
    /**
     * Build an exception for a mapping or re-sync named by something that is
     * not a class implementing its contract.
     *
     * @param  string  $key
     * @param  string  $named
     * @param  class-string  $contract
     * @return self
     */
    #[\Override]
    public static function forClass(string $key, string $named, string $contract): self
    {
        return new self(sprintf('%s names [%s], which is not a class implementing %s, so no provider group can be mapped.', $key, $named, $contract));
    }

    /**
     * Build an exception for a mapping or re-sync configured as a value that is
     * no class name at all: only `null` or blank text names none. The message
     * names the value's type, never the value.
     *
     * @param  string  $key
     * @param  string  $type
     * @param  class-string  $contract
     * @return self
     */
    #[\Override]
    public static function forValue(string $key, string $type, string $contract): self
    {
        $message = '%s holds a value of type [%s], which names no class implementing %s,'
            . ' so no provider group can be mapped: name the class, or leave it null.';

        return new self(sprintf($message, $key, $type, $contract));
    }

    /**
     * Build an exception for a container binding, of the contract or of the
     * class named for it, that resolves to what is no implementation of it.
     *
     * @param  string  $abstract
     * @param  string  $resolved
     * @param  class-string  $contract
     * @return self
     */
    #[\Override]
    public static function forBinding(string $abstract, string $resolved, string $contract): self
    {
        $message = 'The container binding of %s resolves to [%s], which does not implement %s,'
            . ' so no provider group can be mapped.';

        return new self(sprintf($message, $abstract, $resolved, $contract));
    }

    /**
     * Build an exception for a map of groups that is no map of non-empty group
     * names, each to a role's name or a list of them.
     *
     * @param  string  $key
     * @return self
     */
    public static function forMap(string $key): self
    {
        return new self(sprintf('%s maps each non-empty group name to a role\'s name or a list of them, so no provider group can be mapped.', $key));
    }

    /**
     * Build an exception for a re-sync that grants from the group mapping when
     * no mapping is configured, which would otherwise revoke every role the
     * groups gave.
     *
     * @param  string  $key
     * @return self
     */
    public static function forNoMapping(string $key): self
    {
        return new self(sprintf('A re-sync from the group mapping needs a mapping: name one in %s, or map groups in its map.', $key));
    }
}
