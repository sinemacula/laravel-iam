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
     * Where the member's binding of the seam only resolves a key of its own
     * that holds its default (`$defaultKey`), the key must hold one of the
     * member's defaults too, judged the same way, or an instance of exactly one
     * of their classes resolved there, so a class the application names in the
     * member's configuration, which the member binds under that key, is kept.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  string  $abstract
     * @param  list<class-string>  $defaults
     * @param  ?string  $defaultKey
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function isReplaceable(Container $container, string $abstract, array $defaults, ?string $defaultKey = null): bool
    {
        if (!$container->bound($abstract)) {
            return true;
        }

        $closure = $this->bindingOf($container, $abstract);

        if ($closure === null || !in_array($this->declarer(new \ReflectionFunction($closure)), $defaults, true)) {
            return false;
        }

        return $defaultKey === null || $this->isDefaultHeldUnder($container, $defaultKey, $defaults);
    }

    /**
     * Whether the seam holds the member's own binding now: a closure one of the
     * member's defaults declares, never a binding of a default class by its
     * name, and, where the member's binding resolves a key of its own
     * (`$defaultKey`), that key holding one of the member's defaults. A member
     * that binds through a closure never binds the seam to a class name, so a
     * binding of its default class by name is the application's.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  string  $abstract
     * @param  list<class-string>  $defaults
     * @param  ?string  $defaultKey
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function holdsDefault(Container $container, string $abstract, array $defaults, ?string $defaultKey = null): bool
    {
        $closure = $this->bindingOf($container, $abstract);
        $scope   = $closure === null ? null : (new \ReflectionFunction($closure))->getClosureScopeClass()?->getName();

        $isMembers = $scope !== null && $scope !== IlluminateContainer::class && in_array($scope, $defaults, true);

        return $isMembers && ($defaultKey === null || $this->isDefaultHeldUnder($container, $defaultKey, $defaults));
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
     * Return what binds the seam again exactly as it is bound now, for a
     * binding a member that binds its defaults unconditionally may yet bind
     * over: the alias it points to, the instance it holds (one bound with
     * `instance()`, or a shared binding already resolved), or the closure the
     * binding table holds, shared as it is now; `null` when the seam is unbound
     * or the container keeps no binding table to read.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  string  $abstract
     * @return ?\Closure(\Illuminate\Contracts\Container\Container): void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function restorerOf(Container $container, string $abstract): ?\Closure
    {
        if (!$container instanceof IlluminateContainer || !$container->bound($abstract)) {
            return null;
        }

        $closure = $this->bindingOf($container, $abstract);

        // With no closure to read, and no alias, the seam holds an instance,
        // bound or resolved and shared, which the container hands back without
        // building it again
        return match (true) {
            $container->isAlias($abstract) => self::aliasRestorer($abstract, $container->getAlias($abstract)),
            $closure === null              => self::instanceRestorer($abstract, $container->make($abstract)),
            default                        => self::bindingRestorer($abstract, $closure, $container->isShared($abstract)),
        };
    }

    /**
     * What points the seam at the abstract it was an alias of again.
     *
     * @param  string  $abstract
     * @param  string  $target
     * @return \Closure(\Illuminate\Contracts\Container\Container): void
     */
    private static function aliasRestorer(string $abstract, string $target): \Closure
    {
        return static function (Container $app) use ($target, $abstract): void {
            $app->alias($target, $abstract);
        };
    }

    /**
     * What binds the instance the seam held again.
     *
     * @param  string  $abstract
     * @param  mixed  $instance
     * @return \Closure(\Illuminate\Contracts\Container\Container): void
     */
    private static function instanceRestorer(string $abstract, mixed $instance): \Closure
    {
        return static function (Container $app) use ($abstract, $instance): void {
            $app->instance($abstract, $instance);
        };
    }

    /**
     * What binds the closure the seam held again, shared as it was.
     *
     * @param  string  $abstract
     * @param  \Closure(mixed): mixed  $closure
     * @param  bool  $shared
     * @return \Closure(\Illuminate\Contracts\Container\Container): void
     */
    private static function bindingRestorer(string $abstract, \Closure $closure, bool $shared): \Closure
    {
        return static function (Container $app) use ($abstract, $closure, $shared): void {
            $app->bind($abstract, $closure, $shared);
        };
    }

    /**
     * Whether the member's own key holds one of its defaults: it is unbound or
     * bound to one, judged as a seam is (`isReplaceable()`), or holds an
     * instance of exactly one of the defaults' classes, which the member's own
     * scoped binding of the key leaves once something has resolved it (the
     * member's boot, validating its configuration).
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  string  $key
     * @param  list<class-string>  $defaults
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function isDefaultHeldUnder(Container $container, string $key, array $defaults): bool
    {
        if ($this->isReplaceable($container, $key, $defaults)) {
            return true;
        }

        $held = $container instanceof IlluminateContainer && $container->resolved($key) && $container->isShared($key)
            ? $container->make($key)
            : null;

        return is_object($held) && in_array($held::class, $defaults, true);
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
