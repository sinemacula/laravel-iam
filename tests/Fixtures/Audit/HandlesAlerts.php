<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Audit;

/**
 * An alert listener with a `handle()` method, as an application's listener
 * usually has, which keeps each event it is handed in the bound inbox.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class HandlesAlerts
{
    /**
     * Constructor.
     *
     * @param  \Tests\Fixtures\Audit\AlertInbox  $inbox
     */
    public function __construct(

        /** Where each event handed is kept. */
        private AlertInbox $inbox,
    ) {}

    /**
     * Keep the event.
     *
     * @param  object  $event
     * @return void
     */
    public function handle(object $event): void
    {
        $this->inbox->receive(self::class, $event);
    }
}
