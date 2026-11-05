<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Bindings;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use SineMacula\Laravel\Iam\Bindings\Enums\Lifetime;

/**
 * Binds this package's adapters over the members' seams without ever replacing
 * the application's binding (IAM-8.4).
 *
 * It runs once, from a `booting()` callback, after every service provider has
 * registered and before any boots, so a member that binds its defaults with a
 * plain `bind()` has already done so whatever order the providers register in.
 * Each binding whose switch is on is applied with its declared lifetime where
 * the seam is unbound or still bound to the member's own default; anything else
 * is the application's binding, made in a `register()`, and is kept. A binding
 * the application makes in a `boot()` comes later and replaces the adapter.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class BindingRule
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Bindings\MemberDefaults  $defaults
     */
    public function __construct(

        /** Tells a member's default binding from the application's. */
        private MemberDefaults $defaults,
    ) {}

    /**
     * Apply each binding the rule allows, and report what it bound and what it
     * kept. A binding whose switch is off is in neither list.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @param  \SineMacula\Laravel\Iam\Bindings\SeamBinding  ...$bindings
     * @return \SineMacula\Laravel\Iam\Bindings\BindingOutcome
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function apply(Application $app, SeamBinding ...$bindings): BindingOutcome
    {
        $config = $app->make(Repository::class);
        $bound  = [];
        $kept   = [];

        foreach ($bindings as $binding) {

            if ($binding->appliesWhen !== null && !($binding->appliesWhen)($config)) {
                continue;
            }

            if (!$this->defaults->isReplaceable($app, $binding->abstract, $binding->memberDefaults)) {
                $kept[] = $binding->abstract;

                continue;
            }

            $this->bind($app, $binding);

            $bound[] = $binding->abstract;
        }

        return new BindingOutcome($bound, $kept);
    }

    /**
     * Bind the adapter over the seam with the binding's lifetime.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @param  \SineMacula\Laravel\Iam\Bindings\SeamBinding  $binding
     * @return void
     */
    private function bind(Application $app, SeamBinding $binding): void
    {
        match ($binding->lifetime) {
            Lifetime::TRANSIENT => $app->bind($binding->abstract, $binding->adapter),
            Lifetime::SHARED    => $app->singleton($binding->abstract, $binding->adapter),
            Lifetime::SCOPED    => $app->scoped($binding->abstract, $binding->adapter),
        };
    }
}
