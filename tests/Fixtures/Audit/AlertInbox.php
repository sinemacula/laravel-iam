<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Audit;

/**
 * What the alert listeners were handed, in order: each listener's class and the
 * event it was given. A test binds one as an instance, so every listener it
 * resolves writes to the same inbox.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AlertInbox
{
    /** @var list<array{0: class-string, 1: object}> Each listener's class and the event it was handed, in order. */
    private array $received = [];

    /**
     * Keep the event the listener was handed.
     *
     * @param  class-string  $listener
     * @param  object  $event
     * @return void
     */
    public function receive(string $listener, object $event): void
    {
        $this->received[] = [$listener, $event];
    }

    /**
     * Each listener's class and the event it was handed, in order.
     *
     * @return list<array{0: class-string, 1: object}>
     */
    public function received(): array
    {
        return $this->received;
    }
}
