<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Providers;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Iam\Bindings\BindingOutcome;

/**
 * Records, as it boots, whether this package has settled yet, so a test that
 * registers it before every package provider can tell the package settled
 * before the first provider booted.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordsSettlementWhileBooting extends ServiceProvider
{
    /** @var string The container key the record is kept under. */
    public const string RECORDED = 'tests.providers.settled-before-boot';

    /**
     * Record whether the binding rule's outcome is kept yet.
     *
     * @return void
     */
    public function boot(): void
    {
        $this->app->instance(self::RECORDED, $this->app->bound(BindingOutcome::class));
    }
}
