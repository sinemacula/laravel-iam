<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Provisioning;

use Illuminate\Contracts\Queue\ShouldQueue;
use SineMacula\Laravel\Sso\Events\ResultUnlinked;

/**
 * A provisioning listener an application wrongly queues: by the time a queued
 * listener ran, the handoff would be issued and the grant void, so SSO's event
 * refuses to be serialised and queuing it fails at once.
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
