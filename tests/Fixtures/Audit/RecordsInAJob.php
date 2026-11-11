<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Audit;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;

/**
 * A queued job that records the code it is given.
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
     */
    public function __construct(

        /** The code the job records. */
        public string $code,
    ) {}

    /**
     * Record the code.
     *
     * @return void
     */
    public function handle(): void
    {
        AuditLog::record($this->code);
    }
}
