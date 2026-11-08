<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Audit;

/**
 * An invokable alert listener, with no `handle()` method, which keeps each
 * event it is handed in the bound inbox.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class InvokedOnAlerts
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
    public function __invoke(object $event): void
    {
        $this->inbox->receive(self::class, $event);
    }
}
