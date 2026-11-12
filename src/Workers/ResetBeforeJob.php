<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Workers;

use Illuminate\Container\Container;
use Illuminate\Queue\Events\JobProcessing;
use Illuminate\Queue\Jobs\SyncJob;

/**
 * Flushes the worker's session before each queued job; `laravel-authentication`
 * resets its own guards.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ResetBeforeJob
{
    /**
     * Handle the `JobProcessing` event.
     *
     * @param  \Illuminate\Queue\Events\JobProcessing  $event
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function __invoke(JobProcessing $event): void
    {
        // A sync job shares the session of the request that dispatched it.
        if ($event->job instanceof SyncJob) {
            return;
        }

        (new WorkerReset(Container::getInstance()))->flushSession();
    }
}
