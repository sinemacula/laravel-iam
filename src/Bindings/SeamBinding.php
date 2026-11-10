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
 * member class that declares the closure. A member that says itself whether the
 * seam holds its default (`laravel-authorization`'s `isPackageDefault()`) is
 * asked instead (`$holdsDefault`), so a class the application names in its
 * configuration, which it binds through a closure of its own too, is never
 * taken for its default. A binding whose switch is off binds nothing, so a
 * feature the application leaves off changes nothing.
 *
 * The switch reads the configuration as every member will hold it once
 * registered: the application's, with each member's packaged configuration
 * beneath it, so a switch on a member's feature (`sso.features`, MFA's factor
 * types) reads the same whatever order the providers register in, and whether
 * the configuration is cached or not. A value a provider sets after this
 * package registers, or in a `boot()`, is read too late.
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
     * @param  bool|\Closure(): bool  $mandatory
     * @param  list<class-string>  $accepted
     * @param  ?\Closure(\Illuminate\Container\Container, string): bool  $holdsDefault
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

        /** Whether the seam must be bound off its permissive default for the suite to be safe, as the checks report; a closure is asked only when they read it (`isMandatory()`). */
        public bool|\Closure $mandatory = false,

        /** The member's own classes that implement the seam in earnest, which the checks accept on a mandatory seam as they accept the adapter. */
        public array $accepted = [],

        /** The member's own answer to whether the seam holds its default, asked in place of reading the class that declares the binding's closure; `null` for a member that gives none. */
        public ?\Closure $holdsDefault = null,
    ) {}

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
