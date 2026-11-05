<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Workers;

use Illuminate\Container\Container;
use Illuminate\Queue\Events\JobProcessing;
use Illuminate\Queue\Jobs\SyncJob;

/**
 * Starts every queued job with every member's request state flushed.
 *
 * A job run on the `sync` connection runs inside the request or command that
 * dispatched it, which owns that state, so it is left alone, as
 * `laravel-authentication`'s own listener leaves it.
 *
 * The scoped instances are left where they are: the queue worker forgets them
 * itself before it fetches each job, and other `JobProcessing` listeners have
 * already filled some for this job by the time this one runs.
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
        if ($event->job instanceof SyncJob) {
            return;
        }

        (new WorkerReset(Container::getInstance()))->forgetMemberState();
    }
}
