<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Audit;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;

/**
 * A queued job that records the code it is given, as the application's own job
 * records one its mapper or its own code leaves to the caller, and dispatches
 * the next job of a chain when it is given one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordsInAJob implements ShouldQueue
{
    use Dispatchable, Queueable;

    /**
     * Constructor.
     *
     * @param  string  $code
     * @param  ?string  $then
     */
    public function __construct(

        /** The code the job records. */
        public string $code,

        /** The code the job it dispatches records, or `null` for none. */
        public ?string $then = null,
    ) {}

    /**
     * Record the code, then dispatch the next job, if any.
     *
     * @return void
     */
    public function handle(): void
    {
        AuditLog::record($this->code);

        if ($this->then === null) {
            return;
        }

        self::dispatch($this->then);
    }
}
