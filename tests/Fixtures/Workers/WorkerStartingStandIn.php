<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Workers;

/**
 * Stands in for Octane's `WorkerStarting` event, carrying the application.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class WorkerStartingStandIn
{
    /**
     * Constructor.
     *
     * @param  mixed  $app
     */
    public function __construct(

        /** The worker's application, or anything else a test needs. */
        public mixed $app,
    ) {}
}
