<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Bindings;

use Illuminate\Contracts\Config\Repository;
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
 * A member that binds the seam to the class its configuration names
 * (`laravel-authorization`'s `authorization.subject_resolver`, say) names that
 * key (`$configurationKey`): a class the application names there other than the
 * member's defaults is its binding, and kept, though the member makes the
 * binding, in whatever order the providers register.
 *
 * An adapter that must give way to the member's own default while what it
 * answers from is missing names how the container builds it (`$factory`): the
 * closure is bound in the adapter's place, with the row's lifetime, and handed
 * the container, so it answers the adapter or the member's default as the
 * application stands when it is built.
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
     * @param  ?string  $configurationKey
     * @param  ?\Closure(\Illuminate\Contracts\Container\Container): object  $factory
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

        /** The key of the member's configuration that names the class the member binds the seam to; `null` for a seam no configuration names a class for. */
        public ?string $configurationKey = null,

        /** How the container builds the seam, handed the container, when it is not the adapter alone; `null` builds the adapter. */
        public ?\Closure $factory = null,
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

    /**
     * The class the member's configuration names for the seam, read from the
     * configuration given; `null` when the row names no configuration key or
     * the key names no class.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return ?string
     */
    public function configuredClass(Repository $config): ?string
    {
        $class = $this->configurationKey === null ? null : $config->get($this->configurationKey);

        return is_string($class) ? $class : null;
    }

    /**
     * Whether the member's configuration names a class for the seam other than
     * the member's defaults: the application's, which the binding rule keeps.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return bool
     */
    public function namesApplicationClass(Repository $config): bool
    {
        $class = $this->configuredClass($config);

        return $class !== null && !in_array($class, $this->memberDefaults, true);
    }
}
