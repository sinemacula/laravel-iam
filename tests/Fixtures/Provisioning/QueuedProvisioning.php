<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Provisioning;

use Illuminate\Contracts\Queue\ShouldQueue;
use SineMacula\Laravel\Sso\Events\ResultUnlinked;

/**
 * A provisioning listener wrongly queued, which SSO's event refuses.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class QueuedProvisioning implements ShouldQueue
{
    /** @var int How many times a queued listener ran, which is never. */
    public static int $handled = 0;

    /**
     * Provision the result, too late.
     *
     * @param  \SineMacula\Laravel\Sso\Events\ResultUnlinked  $event
     * @return void
     *
     * @SuppressWarnings("php:S1172")
     */
    public function handle(ResultUnlinked $event): void
    {
        self::$handled++;
    }
}
