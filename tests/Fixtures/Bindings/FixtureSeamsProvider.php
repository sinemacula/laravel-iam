<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Bindings;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Iam\Bindings\BindingRule;

/**
 * Applies the binding rule to the fixture seams exactly as this package's
 * service provider applies it to its capabilities' seams: once, from a
 * `booting()` callback, or from its own `boot()` when registered once the
 * booting callbacks have run, while the application boots or after it has
 * booted.
 *
 * The outcome is kept under its own key, so it never collides with the outcome
 * this package's service provider keeps.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FixtureSeamsProvider extends ServiceProvider
{
    /** @var string The key the rule's outcome for the fixture seams is kept under. */
    public const string OUTCOME = 'iam.fixtures.binding-outcome';

    /** @var bool Whether the rule has been applied. */
    private bool $settled = false;

    /**
     * Apply the rule in the booting phase; when already booted, Laravel boots
     * the provider at once, and `boot()` applies it.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        if ($app->isBooted()) {
            return;
        }

        $app->booting(function (): void {

            $this->settle();
        });
    }

    /**
     * Apply the rule now if the booting phase passed before the provider
     * registered.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function boot(): void
    {
        $this->settle();
    }

    /**
     * Apply the rule to the fixture seams and keep its outcome, unless it has
     * been applied already.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function settle(): void
    {
        if ($this->settled) {
            return;
        }

        $seams = (new FixtureSeams)->seams($this->app->make(Repository::class));

        $this->app->instance(self::OUTCOME, $this->app->make(BindingRule::class)->apply($this->app, ...$seams));

        $this->settled = true;
    }
}
