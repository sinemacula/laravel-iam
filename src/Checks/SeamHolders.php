<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Checks;

use Illuminate\Container\Container as IlluminateContainer;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Iam\Bindings\BindingRule;
use SineMacula\Laravel\Iam\Bindings\MemberDefaults;

/**
 * Names the class a seam's live binding answers with, from the container's
 * binding table, without building anything new, so a check can tell a seam left
 * on a member's default from one bound to this package's adapter or the
 * application's own (IAM-10.2).
 *
 * The binding rule's outcome records only what the rule decided as it ran; a
 * binding made afterwards replaces the adapter without changing it, so the live
 * binding is read as well. A class-string binding names the class it was given,
 * followed through the container where that class is bound in turn; this
 * package's scoped adapter, resolved through a key of its own, names the
 * adapter that key holds; a closure a member's own class declares (a member's
 * closure default, from its provider) names that class; an alias names what it
 * points to. An instance, or a shared binding something has already resolved,
 * names the instance the container holds, which reading it hands back without
 * building it again. Any other closure, the application's own or one declared
 * outside any class, cannot be read without building what it returns, which the
 * class declaring it does not tell, so it is named by nothing and `null` is
 * answered: a caller that must know (`MandatorySeamsCheck`) refuses it rather
 * than take it on trust.
 *
 * An anonymous class, bound by its class name or as an instance, is judged by
 * what it is rather than by its debug name, which starts with the contract or
 * the class it is declared against and so would read an implementation of a
 * member's contract as a class of the member's own. One extending a class is
 * named by that class, whose behaviour it inherits, so an anonymous subclass of
 * a member's default is still that default; one extending nothing is the
 * application's own, named by the file and line it is declared at. No member
 * declares an anonymous default.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SeamHolders
{
    /** @var list<string> The namespaces of the members' own classes. */
    private const array MEMBER_NAMESPACES = [
        'SineMacula\Laravel\Authentication\\',
        'SineMacula\Laravel\Authorization\\',
        'SineMacula\Laravel\Mfa\\',
        'SineMacula\Laravel\Sso\\',
        'SineMacula\Laravel\AuditLog\\',
    ];

    /** @var int How many bindings one seam is followed through before nothing is named, so a binding that leads back to itself ends. */
    private const int MAX_DEPTH = 8;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Bindings\MemberDefaults  $defaults
     */
    public function __construct(

        /** Reads the closure the container's binding table holds for a seam. */
        private MemberDefaults $defaults,
    ) {}

    /**
     * The class the seam's live binding answers with, or `null` when it is
     * unbound or its binding names no class.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  string  $abstract
     * @return ?string
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function of(Container $container, string $abstract): ?string
    {
        return $this->follow($container, $abstract, self::MAX_DEPTH);
    }

    /**
     * Follow the seam's binding to the class it names, through at most the
     * given number of bindings.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  string  $abstract
     * @param  int  $depth
     * @return ?string
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function follow(Container $container, string $abstract, int $depth): ?string
    {
        if ($depth === 0 || !$container->bound($abstract) || !$container instanceof IlluminateContainer) {
            return null;
        }

        if ($container->isAlias($abstract)) {
            return $this->follow($container, $container->getAlias($abstract), $depth - 1);
        }

        $closure = $this->defaults->bindingOf($container, $abstract);

        // With no closure to read, the seam holds an instance, bound or
        // resolved and shared, which reading it hands back unbuilt
        return $closure === null ? self::nameOfInstance($container->make($abstract)) : $this->named($container, $abstract, $closure, $depth);
    }

    /**
     * The name an instance the container holds answers with: its class's, or
     * the type of a value that is no object.
     *
     * @param  mixed  $instance
     * @return string
     */
    private static function nameOfInstance(mixed $instance): string
    {
        return is_object($instance) ? self::nameOfClass($instance::class) : get_debug_type($instance);
    }

    /**
     * The class a binding's closure names: the concrete class of a class-string
     * binding, the adapter of this package's scoped one, or the member's class
     * that declares any other; nothing for a closure no member declares.
     *
     * @param  \Illuminate\Container\Container  $container
     * @param  string  $abstract
     * @param  \Closure(mixed): mixed  $closure
     * @param  int  $depth
     * @return ?string
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function named(IlluminateContainer $container, string $abstract, \Closure $closure, int $depth): ?string
    {
        $function  = new \ReflectionFunction($closure);
        $scope     = $function->getClosureScopeClass()?->getName();
        $used      = $function->getClosureUsedVariables();
        $isMembers = $scope !== null && array_filter(self::MEMBER_NAMESPACES, static fn (string $namespace): bool => str_starts_with($scope, $namespace)) !== [];

        return match (true) {
            $scope === IlluminateContainer::class && is_string($used['concrete'] ?? null) => $this->concrete($container, $abstract, $used['concrete'], $depth),
            $scope === BindingRule::class         && is_string($used['key'] ?? null)      => $this->follow($container, $used['key'], $depth - 1),
            $isMembers                                                                    => $scope,
            default                                                                       => null,
        };
    }

    /**
     * The class a class-string binding names: the class itself, unless it is
     * another binding of the container's, which is followed.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  string  $abstract
     * @param  string  $concrete
     * @param  int  $depth
     * @return ?string
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function concrete(Container $container, string $abstract, string $concrete, int $depth): ?string
    {
        if ($concrete === $abstract || !$container->bound($concrete)) {
            return self::nameOfClass($concrete);
        }

        return $this->follow($container, $concrete, $depth - 1);
    }

    /**
     * The name a class answers with: its own, unless it is anonymous, when it
     * is named by the class it extends or, extending nothing, by the file and
     * line it is declared at.
     *
     * @param  string  $class
     * @return string
     */
    private static function nameOfClass(string $class): string
    {
        if (!class_exists($class)) {
            return $class;
        }

        $reflection = new \ReflectionClass($class);

        if (!$reflection->isAnonymous()) {
            return $class;
        }

        $parent = $reflection->getParentClass();

        return $parent !== false ? $parent->getName() : sprintf('class@anonymous (%s:%d)', $reflection->getFileName(), $reflection->getStartLine());
    }
}
