<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Bindings;

/**
 * What one run of the binding rule did: the seams it bound an adapter over and
 * the seams it left with the binding it found, for the checks to report; and
 * the seams it reserved for the rule applied again once every provider has
 * registered, each with the member's default binding it held then, which only
 * they may still be bound over (`BindingRule::reserve()`); and the seams it
 * kept with the application's binding over a member that binds its defaults
 * unconditionally, each with what binds the application's binding again, should
 * that member bind its default over it as it registers
 * (`BindingRule::reclaim()`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class BindingOutcome
{
    /**
     * Constructor.
     *
     * @param  list<class-string>  $bound
     * @param  list<class-string>  $kept
     * @param  array<class-string, \Closure(mixed): mixed>  $reserved
     * @param  array<class-string, \Closure(\Illuminate\Contracts\Container\Container): void>  $restorers
     */
    public function __construct(

        /** The seams bound to this package's adapter. */
        public array $bound,

        /** The seams left with the application's binding. */
        public array $kept,

        /** The seams decided once every provider has registered, each with the exact binding of the member's default it held when reserved. */
        public array $reserved = [],

        /** The seams kept with the application's binding over a member that binds its defaults unconditionally, each with what binds that binding again. */
        public array $restorers = [],
    ) {}
}
