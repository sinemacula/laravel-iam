<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Bindings;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;

/**
 * Finds the application's implementation of one of its contracts that it may
 * either bind in the container or name in the configuration: the provisioner
 * (`Provisioning\ProvisioningSettings`), the memberships and the tenant tree
 * (`Tenancy\TenancyContracts`).
 *
 * The application's binding of the contract, when there is one, wins (IAM-8.4);
 * otherwise it is the class the key names, which must implement the contract.
 * Either is resolved from the container on every call, so whatever the
 * application binds, whenever it binds it, is the one asked, and nothing is
 * kept between calls (IAM-8.1). Naming none (`null`, or blank text) is the
 * application's choice. A class named that is no implementation, a value that
 * is no class name at all (`true`, `false`, a number, an array), or a binding
 * that resolves to no implementation, throws the contract's own exception
 * rather than answer as though there were none.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ConfiguredImplementations
{
    /**
     * The application's implementation of the contract, as bound or as named,
     * or `null` when it has neither.
     *
     * @template T of object
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  class-string<T>  $contract
     * @param  string  $key
     * @param  class-string<\SineMacula\Laravel\Iam\Bindings\Contracts\ReportsMisconfiguration>  $failures
     * @return ?T
     *
     * @throws \LogicException
     */
    public static function find(Container $container, Repository $config, string $contract, string $key, string $failures): ?object
    {
        if ($container->bound($contract)) {
            return self::resolved($container, $contract, $contract, $failures);
        }

        if (!self::isNamed($config, $key)) {
            return null;
        }

        $named = $config->get($key);

        if (!is_string($named)) {
            throw $failures::forValue($key, get_debug_type($named), $contract);
        }

        if (!is_subclass_of($named, $contract)) {
            throw $failures::forClass($key, $named, $contract);
        }

        return self::resolved($container, $named, $contract, $failures);
    }

    /**
     * Whether the application has an implementation of the contract: bound in
     * the container, or named.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  class-string  $contract
     * @param  string  $key
     * @return bool
     */
    public static function isConfigured(Container $container, Repository $config, string $contract, string $key): bool
    {
        return $container->bound($contract) || self::isNamed($config, $key);
    }

    /**
     * Whether the key names anything: any value but `null` and blank text,
     * which alone name none. Whether what it names implements the contract is
     * checked where it is resolved, and fails closed there.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  string  $key
     * @return bool
     */
    public static function isNamed(Repository $config, string $key): bool
    {
        $class = $config->get($key);

        return $class !== null && (!is_string($class) || trim($class) !== '');
    }

    /**
     * Build what the container resolves by the abstract given, which must
     * implement the contract.
     *
     * @template T of object
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  string  $abstract
     * @param  class-string<T>  $contract
     * @param  class-string<\SineMacula\Laravel\Iam\Bindings\Contracts\ReportsMisconfiguration>  $failures
     * @return T
     *
     * @throws \LogicException
     */
    private static function resolved(Container $container, string $abstract, string $contract, string $failures): object
    {
        $resolved = $container->make($abstract);

        return $resolved instanceof $contract ? $resolved : throw $failures::forBinding($abstract, get_debug_type($resolved), $contract);
    }
}
