<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Authorization;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;

/**
 * When `laravel-authentication`'s scope registry and application access are
 * mandatory (IAM-10.2), read from the configuration as it stands: the binding
 * rule declares them as it applies (`AuthorizationSeams`) and `iam:check` reads
 * them again as it runs.
 *
 * - The scope registry is mandatory while any application accepts a machine
 *   credential (IAM-6.5): a guard whose sign-in methods list `api_key` or
 *   `client_credentials`. Left on `laravel-authentication`'s default then
 *   (`AcceptAnyScope`), a credential could be issued scopes that name no
 *   permission, and a typo in one would cap a machine to nothing, or a scope
 *   meant for a later permission would reach it unseen.
 * - Application access is mandatory while `authorization.application_access`
 *   maps an application to the permission to use it (IAM-6.6). Left on
 *   `laravel-authentication`'s default then (`AdmitAnyPrincipal`), every
 *   principal could sign in to that application, refresh and switch there,
 *   whatever its grants say.
 *
 * Which machine credentials a guard accepts is `laravel-authentication`'s
 * application policy's to say (`ApplicationPolicy::allowsMethod()`), which an
 * application may replace to read them from somewhere other than the
 * configuration (a database, a tenant's settings), so the bound policy is asked
 * for each configured guard, once the container is handed in, as `iam:check`
 * hands it; a guard whose settings the policy refuses accepts nothing. Where no
 * container is handed in, or no policy is bound, a guard's methods are read as
 * `laravel-authentication`'s default policy reads them: the guard's own
 * `application.methods` where its `application` block holds that key,
 * `authentication.application.methods` otherwise. A value that is no list of
 * names accepts nothing, as far as the mandate goes; it is
 * `authentication:check`'s to refuse.
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
     * Whether any guard accepts a machine credential, so a credential's scopes
     * must name real permissions: as the bound application policy answers for
     * each guard, where the container given binds one, and as the configuration
     * lists the guard's methods otherwise.
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
     * Whether `authorization.application_access` maps any application to the
     * permission to use it.
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
     * Whether the application policy lets the guard accept a machine
     * credential; a guard whose settings it refuses
     * (`InvalidArgumentException`) accepts nothing, as far as the mandate goes:
     * it is `authentication:check`'s to refuse.
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
                return false;
            }
        }

        return false;
    }

    /**
     * The sign-in methods the guard's configuration lists: its own, where its
     * `application` block holds them, `laravel-authentication`'s default
     * otherwise; none where the value is no list, and only the names in it.
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
