<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Bindings;

use Illuminate\Container\Container as IlluminateContainer;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\AuditLog\AuditLogServiceProvider;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Mfa\MfaServiceProvider;
use SineMacula\Laravel\Sso\SsoServiceProvider;

/**
 * Tells a member's own default binding of a seam from the application's by
 * asking the member (`isPackageDefault()`).
 *
 * An instance, a resolved shared default or an alias the container holds is
 * kept, whatever the member says: binding over it would drop the application's
 * binding or leave the instance with whatever resolved it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class MemberDefaults
{
    /**
     * Whether the seam may be bound over: it is unbound, or holds its member's
     * default, as the member's answer given says.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  string  $abstract
     * @param  \Closure(\Illuminate\Container\Container, string): bool  $holdsDefault
     * @return bool
     */
    public function isReplaceable(Container $container, string $abstract, \Closure $holdsDefault): bool
    {
        return !$container->bound($abstract) || $this->holdsDefault($container, $abstract, $holdsDefault);
    }

    /**
     * The `isPackageDefault()` of the member whose contract the seam is.
     *
     * @param  string  $abstract
     * @return \Closure(\Illuminate\Container\Container, string): bool
     *
     * @throws \InvalidArgumentException
     */
    public static function answerOf(string $abstract): \Closure
    {
        return match (true) {
            str_starts_with($abstract, 'SineMacula\Laravel\Authentication\\') => AuthenticationServiceProvider::isPackageDefault(...),
            str_starts_with($abstract, 'SineMacula\Laravel\Authorization\\')  => AuthorizationServiceProvider::isPackageDefault(...),
            str_starts_with($abstract, 'SineMacula\Laravel\Mfa\\')            => MfaServiceProvider::isPackageDefault(...),
            str_starts_with($abstract, 'SineMacula\Laravel\Sso\\')            => SsoServiceProvider::isPackageDefault(...),
            str_starts_with($abstract, 'SineMacula\Laravel\AuditLog\\')       => AuditLogServiceProvider::isPackageDefault(...),
            default                                                           => throw new \InvalidArgumentException($abstract . ' is no member\'s contract.'),
        };
    }

    /**
     * Whether the seam holds its member's own default, as the member's answer
     * given says, while the binding table still has a binding of it to read.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  string  $abstract
     * @param  \Closure(\Illuminate\Container\Container, string): bool  $holdsDefault
     * @return bool
     */
    public function holdsDefault(Container $container, string $abstract, \Closure $holdsDefault): bool
    {
        return $container instanceof IlluminateContainer && $this->bindingOf($container, $abstract) !== null && $holdsDefault($container, $abstract);
    }

    /**
     * Return the closure the container's binding table holds for the seam, or
     * `null` when there is none to read: the seam is unbound or an alias, holds
     * a shared instance (one bound with `instance()` or one already resolved),
     * or the container keeps no table this can read.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  string  $abstract
     * @return ?\Closure(mixed...): mixed
     */
    public function bindingOf(Container $container, string $abstract): ?\Closure
    {
        if (!$container instanceof IlluminateContainer || $container->isAlias($abstract) || ($container->resolved($abstract) && $container->isShared($abstract))) {
            return null;
        }

        $concrete = $container->getBindings()[$abstract]['concrete'] ?? null;

        return $concrete instanceof \Closure ? $concrete : null;
    }
}
