<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Audit;

/**
 * The caller each queued job running carried from whoever dispatched it
 * (IAM-9.7), innermost last, so the caller's context contributor can fill a
 * job's record from it, as audit-log's job frames keep the actor a job carried.
 *
 * A job enters as it starts, with the caller Laravel has just hydrated into
 * Context from its payload (or none), and leaves as it ends, on success and on
 * failure, by its own identity, with every job inside it: a failed job reports
 * its end twice, and leaving again changes nothing. A sync job inside another
 * enters a frame of its own and, once it has ended, leaves the outer job's
 * caller in force, never the one it left behind in Context. Outside any job
 * there is no carried caller, so a request or a command never reads one a sync
 * job left in Context.
 *
 * It is frame state, as audit-log's job frames are: bound scoped under its own
 * class, so the queue worker and Octane forget it between jobs and requests and
 * it holds one job's or one request's frames alone (IAM-8.1), and outside this
 * package's key for scoped adapters, so `Iam::resetWorkerState()` called
 * between a job's own units of work keeps the caller the job carried.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class JobCallers
{
    /** @var list<array{job: object, caller: ?\SineMacula\Laravel\Iam\Audit\CallerSnapshot}> The jobs running, the innermost last, each with the caller it carried. */
    private array $frames = [];

    /**
     * Enter the job, with the caller it carried, or none.
     *
     * @param  object  $job
     * @param  ?\SineMacula\Laravel\Iam\Audit\CallerSnapshot  $caller
     * @return void
     */
    public function enter(object $job, ?CallerSnapshot $caller): void
    {
        $this->frames[] = ['job' => $job, 'caller' => $caller];
    }

    /**
     * Leave the innermost frame of the job, with every frame inside it; a job
     * with no frame changes nothing.
     *
     * @param  object  $job
     * @return void
     */
    public function leave(object $job): void
    {
        foreach (array_reverse($this->frames, true) as $index => $frame) {

            if ($frame['job'] === $job) {
                $this->frames = array_slice($this->frames, 0, $index);

                return;
            }
        }
    }

    /**
     * The caller the innermost job carried, or `null` outside any job and for a
     * job that carried none.
     *
     * @return ?\SineMacula\Laravel\Iam\Audit\CallerSnapshot
     */
    public function current(): ?CallerSnapshot
    {
        return $this->frames === [] ? null : $this->frames[array_key_last($this->frames)]['caller'];
    }
}
