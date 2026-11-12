<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Authorization;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;

/**
 * Whether `laravel-authentication`'s scope registry and application access must
 * be bound, read from the configuration.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AccessMandates
{
    /** @var list<string> The sign-in methods by which a guard accepts a machine credential. */
    public const array MACHINE_METHODS = ['api_key', 'client_credentials'];

    /** @var string The setting mapping each application to the permission to use it. */
    public const string APPLICATION_ACCESS = 'authorization.application_access';

    /**
     * Whether any guard accepts a machine credential.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  ?\Illuminate\Contracts\Container\Container  $container
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public static function acceptsMachineCredentials(Repository $config, ?Container $container = null): bool
    {
        $guards = $config->get('auth.guards');

        if (!is_array($guards)) {
            return false;
        }

        $policy = $container?->bound(ApplicationPolicy::class) ? $container->make(ApplicationPolicy::class) : null;

        foreach ($guards as $name => $guard) {

            $accepts = $policy instanceof ApplicationPolicy
                ? self::isMachineGuard($policy, (string) $name)
                : array_intersect(self::MACHINE_METHODS, self::methodsOf($config, $guard)) !== [];

            if ($accepts) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether `authorization.application_access` maps any application.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return bool
     */
    public static function namesApplicationAccess(Repository $config): bool
    {
        $access = $config->get(self::APPLICATION_ACCESS);

        return is_array($access) && $access !== [];
    }

    /**
     * Whether the policy lets the guard accept a machine credential.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy  $policy
     * @param  string  $guard
     * @return bool
     */
    private static function isMachineGuard(ApplicationPolicy $policy, string $guard): bool
    {
        foreach (self::MACHINE_METHODS as $method) {

            try {
                if ($policy->allowsMethod($guard, $method)) {
                    return true;
                }
            } catch (\InvalidArgumentException) {
                // `authentication:check` reports refused guard settings.
                return false;
            }
        }

        return false;
    }

    /**
     * The guard's sign-in methods, else `laravel-authentication`'s default.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  mixed  $guard
     * @return array<array-key, string>
     */
    private static function methodsOf(Repository $config, mixed $guard): array
    {
        $application = is_array($guard) ? ($guard['application'] ?? null) : null;

        $methods = is_array($application) && array_key_exists('methods', $application)
            ? $application['methods']
            : $config->get('authentication.application.methods');

        return is_array($methods) ? array_filter($methods, is_string(...)) : [];
    }
}
