<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Support\Facades\Event;

/**
 * Reads the listeners registered for an event as they were registered, for the
 * tests that check which listeners the package registers.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait ReadsRawListeners
{
    /**
     * The listeners registered for the event, as they were registered; none
     * when nothing listens for it.
     *
     * @param  string  $event
     * @return array<array-key, mixed>
     */
    private static function rawListenersOf(string $event): array
    {
        $listeners = Event::getRawListeners()[$event] ?? [];

        self::assertIsArray($listeners);

        return $listeners;
    }
}
