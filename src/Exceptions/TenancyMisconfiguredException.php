<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Exceptions;

use SineMacula\Laravel\Iam\Bindings\Contracts\ReportsMisconfiguration;

/**
 * Thrown when the application's memberships or tenant tree cannot be built
 * (IAM-7.4, IAM-7.5): `iam.tenancy.memberships` or `iam.tenancy.tree` names
 * what is no class implementing its contract, holds a value that is no class
 * name at all, the container binding it is resolved by resolves to what is no
 * such implementation, an adapter that answers from the memberships is asked
 * while none is configured, or the tree places a tenant below one of another
 * type, which `laravel-authorization` cannot read.
 *
 * It is thrown where a member asks, inside the member's transaction, so the
 * link, the redemption or the change being judged fails rather than proceed as
 * though the identity held no membership or the tenant stood alone. The message
 * names the configuration key, the binding or the tenant types, never a tenant
 * or an identity.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final class TenancyMisconfiguredException extends \LogicException implements ReportsMisconfiguration
{
    /**
     * Build an exception for an implementation named by something that is not a
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
        return new self(sprintf('%s names [%s], which is not a class implementing %s.', $key, $named, $contract));
    }

    /**
     * Build an exception for an implementation configured as a value that is no
     * class name at all (`true`, `false`, a number, an array): only `null` or
     * blank text names none. The message names the value's type, never the
     * value.
     *
     * @param  string  $key
     * @param  string  $type
     * @param  class-string  $contract
     * @return self
     */
    #[\Override]
    public static function forValue(string $key, string $type, string $contract): self
    {
        return new self(sprintf('%s holds a value of type [%s], which names no class implementing %s: name the class, or leave it null.', $key, $type, $contract));
    }

    /**
     * Build an exception for a container binding, of the contract or of the
     * class named for it, that resolves to what does not implement it: the
     * binding is at fault, not the configuration key.
     *
     * @param  string  $abstract
     * @param  string  $resolved
     * @param  class-string  $contract
     * @return self
     */
    #[\Override]
    public static function forBinding(string $abstract, string $resolved, string $contract): self
    {
        return new self(sprintf('The container binding of %s resolves to [%s], which does not implement %s.', $abstract, $resolved, $contract));
    }

    /**
     * Build an exception for an adapter asked to answer from an implementation
     * the application neither names nor binds, which it never guesses.
     *
     * @param  string  $key
     * @param  class-string  $contract
     * @return self
     */
    public static function forNone(string $key, string $contract): self
    {
        return new self(sprintf('Nothing implements %s: name the class in %s, or bind it in the container.', $contract, $key));
    }

    /**
     * Build an exception for a tenant tree that places a tenant below one of
     * another type, which `laravel-authorization`, reading every tenant of a
     * subtree as the type of the tenant at its top, cannot be given. The
     * message names the two types, never a tenant.
     *
     * @param  string  $type
     * @param  string  $otherType
     * @return self
     */
    public static function forMixedTree(string $type, string $otherType): self
    {
        return new self(sprintf('The tenant tree nests a tenant of type [%s] with one of type [%s]: every tenant of the tree must be of one type.', $type, $otherType));
    }
}
