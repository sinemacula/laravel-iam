<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Bindings;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Iam\Bindings\BindingRule;

/**
 * Applies the binding rule to the fixture seams exactly as this package's
 * service provider applies it to its capabilities' seams: once, as it
 * registers, whenever that is.
 *
 * The outcome is kept under its own key, so it never collides with the outcome
 * this package's service provider keeps, and so is the configuration the rule
 * read the fixture seams' switches from.
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

    /** @var string The key the configuration the switches were read from is kept under. */
    public const string SWITCHES = 'iam.fixtures.binding-switches';

    /**
     * Apply the rule to the fixture seams and keep its outcome and the
     * configuration it read their switches from.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    #[\Override]
    public function register(): void
    {
        $seams = new FixtureSeams;

        $this->app->instance(self::OUTCOME, $this->app->make(BindingRule::class)->apply($this->app, $seams));
        $this->app->instance(self::SWITCHES, $seams->switches);
    }
}
