<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Audit;

use Illuminate\Container\Container;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Log\Context\Events\ContextDehydrating;
use Illuminate\Log\Context\Repository;
use Illuminate\Queue\Events\JobExceptionOccurred;
use Illuminate\Queue\Events\JobFailed;
use Illuminate\Queue\Events\JobProcessed;
use Illuminate\Queue\Events\JobProcessing;
use Illuminate\Support\Facades\Event;

/**
 * Carries the `laravel-authentication` caller into every queued job its
 * dispatcher queues, and keeps it for the job's records (IAM-9.7).
 *
 * Audit-log carries the ambient actor into a job itself, but reads it only from
 * a guard using Laravel's `GuardHelpers`, which `laravel-authentication`'s
 * guards do not, so a job dispatched by a caller on a `jwt` or `api_key` guard
 * carries no actor of audit-log's; and the worker reset (IAM-11.3) forgets
 * every package guard's binding before the job runs, so no guard holds the
 * caller there either. Without the caller carried here, every record such a job
 * leaves to the caller would name no one.
 *
 * As the payload is made (`ContextDehydrating`), the caller a guard holds
 * (`HeldCaller`), or else, inside a job, the caller that job carried, so a
 * chain of jobs keeps naming who started it, is carried on the copy of Context
 * the payload is made from, never on the scoped repository, under one hidden
 * key (`CallerSnapshot::KEY`); with none, the key is dropped, so a caller a
 * sync job left in Context is not sent on. This runs inside the application's
 * `dispatch()`, so guards that cannot be read (a driver that cannot be built)
 * carry no caller rather than stop the job being queued: audit-log's own
 * carrying walks the same guards and reports the failure, so it is not reported
 * twice. An `\Error`, a defect rather than a configuration, is let through. It
 * is the caller as the guard holds it, read as the contributor reads it, never
 * triggering authentication, and it is carried beside audit-log's own envelope,
 * whatever order the two listeners run in: audit-log carries an actor only from
 * a guard this never reads, so at most one of them names anyone.
 *
 * As a job starts (`JobProcessing`, after Laravel has hydrated Context from its
 * payload) it enters a frame of `JobCallers` with the caller it carried, which
 * it leaves as it ends (`JobProcessed`, `JobFailed`, `JobExceptionOccurred`),
 * so the contributor reads the caller of the job running and no other. The
 * frame is left from a listener registered once the application has booted,
 * after every listener any provider's `boot()` adds, as audit-log leaves its
 * own job frame: an application recording a job's end, its failure or its retry
 * is still inside both frames, so its record has the job's origin and the
 * caller the job carried alike. Each listener resolves what it uses from the
 * application current when it runs, so under Octane a sync job reads the
 * request's sandbox.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CarryCallerIntoJobs
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Audit\HeldCaller  $held
     * @param  \SineMacula\Laravel\Iam\Audit\JobCallers  $jobs
     */
    public function __construct(

        /** The caller a guard holds now. */
        private HeldCaller $held,

        /** The caller each job running carried. */
        private JobCallers $jobs,
    ) {}

    /**
     * Register the listeners carrying the caller into each job's payload and
     * entering each job's frame, from this package's `boot()`, and the one
     * leaving it once the application has booted, after every listener any
     * provider's `boot()` adds to a job's end.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     */
    public static function listen(Application $app): void
    {
        Event::listen(ContextDehydrating::class, static function (ContextDehydrating $event): void {

            try {
                self::current()->carry($event->context);
            } catch (\Exception) {
                // A guard that cannot be read must not stop the job being
                // queued: it carries no caller, and audit-log's own carrying,
                // which walks the same guards, reports the failure
                CallerSnapshot::forgetIn($event->context);
            }
        });

        Event::listen(JobProcessing::class, static function (JobProcessing $event): void {

            self::current()->enter($event->job, Container::getInstance()->make(Repository::class));
        });

        $app->booted(static function (): void {

            Event::listen([JobProcessed::class, JobFailed::class, JobExceptionOccurred::class], static function (JobExceptionOccurred|JobFailed|JobProcessed $event): void {

                self::current()->leave($event->job);
            });
        });
    }

    /**
     * Carry the caller a guard holds, or else the one the job running carried,
     * in the Context a job's payload is made from; drop any caller it holds
     * when there is none.
     *
     * @param  \Illuminate\Log\Context\Repository  $context
     * @return void
     */
    private function carry(Repository $context): void
    {
        $caller = $this->held->current() ?? $this->jobs->current();

        CallerSnapshot::forgetIn($context);

        if ($caller === null) {
            return;
        }

        $caller->carryInto($context);
    }

    /**
     * Enter the job's frame, with the caller the Context hydrated from its
     * payload carries.
     *
     * @param  object  $job
     * @param  \Illuminate\Log\Context\Repository  $context
     * @return void
     */
    private function enter(object $job, Repository $context): void
    {
        $this->jobs->enter($job, CallerSnapshot::carriedIn($context));
    }

    /**
     * Leave the job's frame.
     *
     * @param  object  $job
     * @return void
     */
    private function leave(object $job): void
    {
        $this->jobs->leave($job);
    }

    /**
     * This listener, as the application current now builds it.
     *
     * @return self
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private static function current(): self
    {
        return Container::getInstance()->make(self::class);
    }
}
