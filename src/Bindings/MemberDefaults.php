<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Bindings;

use Illuminate\Container\Container as IlluminateContainer;
use Illuminate\Contracts\Container\Container;

/**
 * Tells a member's own default binding of a seam from the application's, by
 * reading the container's binding table.
 *
 * Most members expose no test of their defaults, so the container's table is
 * the only public source for them. A class-string binding is held as the
 * closure Laravel builds for it, which carries the concrete class it was given
 * as a used variable; a closure binding carries the class that lexically
 * declared it as its scope. A member that answers itself whether a seam holds
 * its default (`laravel-authorization`'s `isPackageDefault()`) is asked
 * instead, since it binds a class the application names in its configuration
 * through a closure of its own too.
 *
 * An instance or an alias the container holds is kept, whatever the table says:
 * Laravel's `instance()` and `alias()` leave the binding beneath them in place,
 * and binding over either would drop the application's. A shared default
 * something has already resolved is kept too, since whatever resolved it holds
 * that instance, which a new binding would not replace.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class MemberDefaults
{
    /**
     * Whether the seam may be bound over: it is unbound, or bound to one of the
     * member's defaults. A member that answers whether the seam holds its
     * default is asked (`holdsDefault()`); for any other, the default is a
     * class-string binding to one of the defaults given, or a closure one of
     * them declares. An instance, a resolved shared default, an alias, or any
     * other binding is kept.
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
     * Whether the seam holds its member's own default now, as the member's own
     * answer given says (`laravel-authorization`'s `isPackageDefault()`). The
     * member is asked only while the binding table has a binding of the seam to
     * read: an instance, a resolved shared binding or an alias held over the
     * member's default leaves that default in the table, so is never taken for
     * it.
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
