<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Bindings;

use SineMacula\Laravel\Iam\Bindings\Enums\Lifetime;

/**
 * One member seam this package binds an adapter over, declared as data so the
 * binding rule applies every binding in one place.
 *
 * The rule binds the adapter only where the seam is unbound or still bound to
 * the member's own default, as the member whose contract the seam is says (its
 * `isPackageDefault()`, `$holdsDefault`), so an application's binding is never
 * replaced. A binding whose switch is off binds nothing, so a feature the
 * application leaves off changes nothing.
 *
 * The switch reads the configuration as every member will hold it once
 * registered: the application's, with each member's packaged configuration
 * beneath it, so a switch on a member's feature (`sso.features`, MFA's factor
 * types) reads the same whatever order the providers register in, and whether
 * the configuration is cached or not. A value a provider sets after this
 * package registers, or in a `boot()`, is read too late.
 *
 * An adapter that must give way to the member's own default while what it
 * answers from is missing names how the container builds it (`$factory`): the
 * closure is bound in the adapter's place, with the row's lifetime, and handed
 * the container, so it answers the adapter or the member's default as the
 * application stands when it is built.
 *
 * A binding over a member's seam that the member reports on can declare the
 * adapter to that member once bound (`$declare`): the rule hands it the closure
 * the container now holds for the seam, the very one it registered, so the
 * member's report can tell the adapter, still bound, from a binding made over
 * it later. A binding the rule keeps, or whose switch is off, binds nothing and
 * declares nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SeamBinding
{
    /** @var \Closure(\Illuminate\Container\Container, string): bool Whether the seam holds its member's default, as the member says. */
    public \Closure $holdsDefault;

    /**
     * Constructor.
     *
     * @param  class-string  $abstract
     * @param  class-string  $adapter
     * @param  list<class-string>  $memberDefaults
     * @param  \SineMacula\Laravel\Iam\Bindings\Enums\Lifetime  $lifetime
     * @param  ?\Closure(\Illuminate\Contracts\Config\Repository): bool  $appliesWhen
     * @param  bool|\Closure(): bool  $mandatory
     * @param  ?\Closure(\Illuminate\Container\Container, string): bool  $holdsDefault
     * @param  ?\Closure(\Illuminate\Contracts\Container\Container): object  $factory
     * @param  ?\Closure(\Illuminate\Contracts\Container\Container, (\Closure(mixed...): mixed)|null): void  $declare
     */
    public function __construct(

        /** The member's contract. */
        public string $abstract,

        /** This package's implementation of the contract. */
        public string $adapter,

        /** The member's own default classes. */
        public array $memberDefaults,

        /** How long the container keeps the adapter. */
        public Lifetime $lifetime = Lifetime::TRANSIENT,

        /** The switch that turns the binding on, read from configuration; `null` is always on. */
        public ?\Closure $appliesWhen = null,

        /** Whether the seam must be bound off its permissive default for the suite to be safe, as the checks report; a closure is asked only when they read it (`isMandatory()`). */
        public bool|\Closure $mandatory = false,

        // The answer given in place of the member's own `isPackageDefault()`.
        ?\Closure $holdsDefault = null,

        /** How the container builds the seam, handed the container, when it is not the adapter alone; `null` builds the adapter. */
        public ?\Closure $factory = null,

        /** Declares the adapter to the member's own report once the rule has bound it, handed the container and the closure bound over the seam; `null` declares nothing. */
        public ?\Closure $declare = null,
    ) {
        $this->holdsDefault = $holdsDefault ?? MemberDefaults::answerOf($abstract);
    }

    /**
     * Whether the seam must be bound off its permissive default, asking the
     * closure the row was given, if any, only now: a mandate that asks a
     * service the application binds (`laravel-authentication`'s application
     * policy) is read when the checks run, never while providers register or on
     * each boot, when the binding rule reads the rows.
     *
     * @return bool
     */
    public function isMandatory(): bool
    {
        return $this->mandatory instanceof \Closure ? ($this->mandatory)() : $this->mandatory;
    }
}
