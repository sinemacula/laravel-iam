<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Workers;

/**
 * Stands in for Octane's `WorkerStarting` event, which is dispatched by name
 * since Octane is not installed: it carries the worker's application as
 * Octane's event does.
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
