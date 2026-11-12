<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Workers;

use Illuminate\Container\Container;

/**
 * Resets the application an Octane worker clones each request's sandbox from.
 *
 * Registered by the event's name, so Octane stays optional.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ResetWhenWorkerStarts
{
    /** @var string The Octane event the listener is registered for. */
    public const string EVENT = 'Laravel\Octane\Events\WorkerStarting';

    /**
     * Handle Octane's `WorkerStarting` event.
     *
     * @param  object  $event
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function __invoke(object $event): void
    {
        $app = property_exists($event, 'app') ? $event->app : null;

        (new WorkerReset($app instanceof Container ? $app : Container::getInstance()))->reset();
    }
}
