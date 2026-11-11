<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Bindings;

use Illuminate\Container\Container as IlluminateContainer;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\AuditLog\AuditLogServiceProvider;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Mfa\MfaServiceProvider;

/**
 * Tells a member's own default binding of a seam from the application's: by
 * asking the member (`isPackageDefault()`) where it answers, and by reading the
 * container's binding table for SSO, which does not.
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
     * Whether the seam may be bound over: it is unbound, or holds one of the
     * member's defaults, as the member's answer given says or, without one, as
     * a class-string binding to one of the defaults given, or a closure one of
     * them declares.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  string  $abstract
     * @param  list<class-string>  $defaults
     * @param  ?\Closure(\Illuminate\Container\Container, string): bool  $holdsDefault
     * @return bool
     */
    public function isReplaceable(Container $container, string $abstract, array $defaults, ?\Closure $holdsDefault = null): bool
    {
        if (!$container->bound($abstract)) {
            return true;
        }

        if ($holdsDefault !== null) {
            return $this->holdsDefault($container, $abstract, $holdsDefault);
        }

        $closure = $this->bindingOf($container, $abstract);

        return $closure !== null && in_array($this->declarer(new \ReflectionFunction($closure)), $defaults, true);
    }

    /**
     * The `isPackageDefault()` of the member whose contract the seam is, or
     * `null` for SSO and any other, which give none.
     *
     * @param  string  $abstract
     * @return ?\Closure(\Illuminate\Container\Container, string): bool
     */
    public static function answerOf(string $abstract): ?\Closure
    {
        return match (true) {
            str_starts_with($abstract, 'SineMacula\Laravel\Authentication\\') => AuthenticationServiceProvider::isPackageDefault(...),
            str_starts_with($abstract, 'SineMacula\Laravel\Authorization\\')  => AuthorizationServiceProvider::isPackageDefault(...),
            str_starts_with($abstract, 'SineMacula\Laravel\Mfa\\')            => MfaServiceProvider::isPackageDefault(...),
            str_starts_with($abstract, 'SineMacula\Laravel\AuditLog\\')       => AuditLogServiceProvider::isPackageDefault(...),
            default                                                           => null,
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
     * or the container keeps no table this can read. Each binding the container
     * makes is a closure of its own, so the closure tells one binding of the
     * seam from any later one, even of the same class.
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

    /**
     * Return the class a binding's closure names: the concrete class it was
     * given, for the closure Laravel builds around a class-string binding, or
     * else the class that lexically declares the closure (`null` for none).
     *
     * @param  \ReflectionFunction  $closure
     * @return ?string
     */
    private function declarer(\ReflectionFunction $closure): ?string
    {
        $scope    = $closure->getClosureScopeClass()?->getName();
        $concrete = $closure->getClosureUsedVariables()['concrete'] ?? null;

        if ($scope === IlluminateContainer::class && is_string($concrete)) {
            return $concrete;
        }

        return $scope;
    }
}
