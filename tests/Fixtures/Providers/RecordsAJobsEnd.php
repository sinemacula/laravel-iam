<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Providers;

use Illuminate\Queue\Events\JobExceptionOccurred;
use Illuminate\Queue\Events\JobFailed;
use Illuminate\Queue\Events\JobProcessed;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;

/**
 * An application's provider, booted after this package's, that records a job's
 * end from its own `boot()`, as an application auditing a job's completion, its
 * failure or its retry does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordsAJobsEnd extends ServiceProvider
{
    /** @var string The code a job's end is recorded under. */
    public const string CODE = 'iam_test.job_end';

    /**
     * Listen for every way a job ends, recording each.
     *
     * @return void
     */
    public function boot(): void
    {
        Event::listen([JobProcessed::class, JobFailed::class, JobExceptionOccurred::class], static function (): void {

            AuditLog::record(self::CODE);
        });
    }
}
