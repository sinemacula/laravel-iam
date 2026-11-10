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
 * The switch reads the configuration as every member will hold it once
 * registered: the application's, with each member's packaged configuration
 * beneath it, so a switch on a member's feature (`sso.features`, MFA's factor
 * types) reads the same whatever order the providers register in, and whether
 * the configuration is cached or not. A value a provider sets after this
 * package registers, or in a `boot()`, is read too late.
 *
 * A member that binds the seam to a closure resolving a key of its own, which
 * holds the default its configuration names (`laravel-authorization`'s
 * `authorization.default:*` keys), names that key (`$defaultKey`): the seam is
 * then the member's only while the closure is one a class in `$memberDefaults`
 * declares and the key still holds one of them, so a class the application
 * names in the member's configuration is its binding, and kept, though the
 * member made the binding.
 *
 * An adapter that must give way to the member's own default while what it
 * answers from is missing names how the container builds it (`$factory`): the
 * closure is bound in the adapter's place, with the row's lifetime, and handed
 * the container, so it answers the adapter or the member's default as the
 * application stands when it is built.
 *
 * A member that listens for its seam being bound again, but only where the seam
 * is still unbound as it registers (`laravel-authorization` forgets the
 * resolutions read through its subject resolver or tenant tree), names that
 * listener (`$rebinding`): binding the adapter over a seam that is still
 * unbound, before the member registers, registers it first, as the member would
 * have, so the seam is listened for in every provider order.
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
     * @param  ?string  $defaultKey
     * @param  ?\Closure(\Illuminate\Contracts\Container\Container): object  $factory
     * @param  ?\Closure(): void  $rebinding
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

        /** The key the member holds its default under when its binding of the seam only resolves that key, which must still hold one of the member's defaults for the seam to be the member's; `null` for a seam bound to its default directly. */
        public ?string $defaultKey = null,

        /** How the container builds the seam, handed the container, when it is not the adapter alone; `null` builds the adapter. */
        public ?\Closure $factory = null,

        /** What the member does when the seam is bound again, registered only where the seam is still unbound as the adapter is bound over it; `null` for none. */
        public ?\Closure $rebinding = null,
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
