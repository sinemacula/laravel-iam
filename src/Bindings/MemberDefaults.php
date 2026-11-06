<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Bindings;

use Illuminate\Container\Container as IlluminateContainer;
use Illuminate\Contracts\Container\Container;

/**
 * Tells a member's own default binding of a seam from the application's, by
 * reading the container's binding table.
 *
 * No member exposes its defaults as data, so the container's table is the only
 * public source. A class-string binding is held as the closure Laravel builds
 * for it, which carries the concrete class it was given as a used variable; a
 * closure binding carries the class that lexically declared it as its scope.
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
     * member's defaults, by a class-string binding to one of them or by a
     * closure one of them declares. An instance, a resolved shared default, an
     * alias, or any other binding is kept.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  string  $abstract
     * @param  list<class-string>  $defaults
     * @return bool
     */
    public function isReplaceable(Container $container, string $abstract, array $defaults): bool
    {
        if (!$container->bound($abstract)) {
            return true;
        }

        $closure = $this->bindingOf($container, $abstract);

        return $closure !== null && in_array($this->declarer(new \ReflectionFunction($closure)), $defaults, true);
    }

    /**
     * Return the closure the container's binding table holds for the seam, or
     * `null` when there is none to read: the seam is an alias, holds a shared
     * instance (one bound with `instance()` or one already resolved), or the
     * container keeps no table this can read.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  string  $abstract
     * @return ?\Closure(mixed...): mixed
     */
    private function bindingOf(Container $container, string $abstract): ?\Closure
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
