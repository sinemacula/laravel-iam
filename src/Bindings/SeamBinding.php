<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Bindings;

use SineMacula\Laravel\Iam\Bindings\Enums\Lifetime;

/**
 * One member seam this package binds an adapter over, declared as data so the
 * binding rule applies every binding in one place.
 *
 * The rule binds the adapter only where the seam is unbound or still bound to
 * one of the member's own defaults, so an application's binding is never
 * replaced. A member default is named by the concrete class a class-string
 * binding was given or, for a binding the member made with a closure, by the
 * member class that declares the closure. A binding whose switch is off binds
 * nothing, so a feature the application leaves off changes nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SeamBinding
{
    /**
     * Constructor.
     *
     * @param  class-string  $abstract
     * @param  class-string  $adapter
     * @param  list<class-string>  $memberDefaults
     * @param  \SineMacula\Laravel\Iam\Bindings\Enums\Lifetime  $lifetime
     * @param  ?\Closure(\Illuminate\Contracts\Config\Repository): bool  $appliesWhen
     * @param  bool  $mandatory
     */
    public function __construct(

        /** The member's contract. */
        public string $abstract,

        /** This package's implementation of the contract. */
        public string $adapter,

        /** The member's own default concretes, or the member classes that declare its closure bindings. */
        public array $memberDefaults,

        /** How long the container keeps the adapter. */
        public Lifetime $lifetime = Lifetime::TRANSIENT,

        /** The switch that turns the binding on, read from configuration; `null` is always on. */
        public ?\Closure $appliesWhen = null,

        /** Whether the seam must be bound off its permissive default for the suite to be safe, as the checks report. */
        public bool $mandatory = false,
    ) {}
}
