<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Exceptions;

use SineMacula\Laravel\Iam\Bindings\Contracts\ReportsMisconfiguration;

/**
 * Thrown when the application's tenant MFA requirement cannot be built
 * (IAM-4.5): `iam.tenancy.mfa_requirement` names what is no class implementing
 * `Contracts\TenantMfaRequirement`, holds a value that is no class name at all,
 * or the container binding it is resolved by resolves to what is no such
 * requirement.
 *
 * It is thrown where a member asks what a tenant requires, inside the member's
 * transaction, so the sign-in, refresh or change being judged fails rather than
 * proceed as though the tenant required nothing. The message names the
 * configuration key or the binding, never a tenant or an identity.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final class TenantMfaRequirementMisconfiguredException extends \LogicException implements ReportsMisconfiguration
{
    /**
     * Build an exception for a requirement named by something that is not a
     * class implementing the contract.
     *
     * @param  string  $key
     * @param  string  $named
     * @param  class-string  $contract
     * @return self
     */
    #[\Override]
    public static function forClass(string $key, string $named, string $contract): self
    {
        $message = '%s names [%s], which is not a class implementing %s, so no tenant\'s MFA requirement can be answered.';

        return new self(sprintf($message, $key, $named, $contract));
    }

    /**
     * Build an exception for a requirement configured as a value that is no
     * class name at all (`true`, `false`, a number, an array): only `null` or
     * blank text names no requirement, so any other value is a
     * misconfiguration, never a choice of none. The message names the value's
     * type, never the value.
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
            . ' so no tenant\'s MFA requirement can be answered: name the class, or leave it null to require nothing.';

        return new self(sprintf($message, $key, $type, $contract));
    }

    /**
     * Build an exception for a container binding, of the contract or of the
     * class named for it, that resolves to what is no tenant MFA requirement:
     * the binding is at fault, not the configuration key.
     *
     * @param  string  $abstract
     * @param  string  $resolved
     * @param  class-string  $contract
     * @return self
     */
    #[\Override]
    public static function forBinding(string $abstract, string $resolved, string $contract): self
    {
        $message = 'The container binding of %s resolves to [%s], which is no tenant MFA requirement,'
            . ' so no tenant\'s MFA requirement can be answered: bind it to a class implementing %s.';

        return new self(sprintf($message, $abstract, $resolved, $contract));
    }
}
