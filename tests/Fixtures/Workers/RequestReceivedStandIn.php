<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Workers;

/**
 * Stands in for Octane's `RequestReceived` event, carrying the sandbox.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RequestReceivedStandIn
{
    /**
     * Constructor.
     *
     * @param  mixed  $sandbox
     */
    public function __construct(

        /** The application the request runs in, or anything else a test needs. */
        public mixed $sandbox,
    ) {}
}
