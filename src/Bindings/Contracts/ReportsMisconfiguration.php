<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Bindings\Contracts;

/**
 * Builds the exception for an implementation of one of the application's
 * contracts that cannot be built (`Bindings\ConfiguredImplementations`): its
 * configuration key names what is no class implementing the contract, holds a
 * value that is no class name at all, or the container binding it is resolved
 * by resolves to what does not implement it.
 *
 * Each contract the application names in the configuration has an exception of
 * its own implementing this, whose message says what cannot be done without the
 * implementation. A message names the configuration key, the binding or a
 * value's type, never the value, a tenant or an identity.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
interface ReportsMisconfiguration
{
    /**
     * Build an exception for an implementation named by something that is not a
     * class implementing the contract.
     *
     * @param  string  $key
     * @param  string  $named
     * @param  class-string  $contract
     * @return \LogicException
     */
    public static function forClass(string $key, string $named, string $contract): \LogicException;

    /**
     * Build an exception for an implementation configured as a value that is no
     * class name at all (`true`, `false`, a number, an array): only `null` or
     * blank text names none, so any other value is a misconfiguration, never a
     * choice of none.
     *
     * @param  string  $key
     * @param  string  $type
     * @param  class-string  $contract
     * @return \LogicException
     */
    public static function forValue(string $key, string $type, string $contract): \LogicException;

    /**
     * Build an exception for a container binding that resolves to what does not
     * implement the contract.
     *
     * @param  string  $abstract
     * @param  string  $resolved
     * @param  class-string  $contract
     * @return \LogicException
     */
    public static function forBinding(string $abstract, string $resolved, string $contract): \LogicException;
}
