<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Providers;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Iam\Bindings\BindingOutcome;

/**
 * Records, as it registers, whether the binding rule's outcome is kept yet, so
 * a test that registers it straight after this package's provider can tell the
 * rule ran in this package's `register()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordsBindingOutcome extends ServiceProvider
{
    /** @var string The container key the record is kept under. */
    public const string RECORDED = 'tests.providers.bound-as-registered';

    /**
     * Record whether the binding rule's outcome is kept yet.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        $this->app->instance(self::RECORDED, $this->app->bound(BindingOutcome::class));
    }
}
