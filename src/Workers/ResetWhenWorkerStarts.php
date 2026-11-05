<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Workers;

use Illuminate\Container\Container;
use Illuminate\Contracts\Container\Container as ContainerContract;

/**
 * Starts every Octane worker with every member's request state flushed from the
 * application its requests' sandboxes are cloned from.
 *
 * It listens to `Laravel\Octane\Events\WorkerStarting` by name, so Octane stays
 * optional. Anything the worker's boot left in a member's scoped instance would
 * otherwise be cloned into the first request's sandbox, before Octane first
 * forgets the worker application's scoped instances at the end of an
 * operation; the reset runs on the event's `app` where it carries one.
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
        (new WorkerReset(self::applicationOf($event)))->reset();
    }

    /**
     * Return the worker's application: the event's `app` when it is a
     * container, otherwise the current one.
     *
     * @param  object  $event
     * @return \Illuminate\Contracts\Container\Container
     */
    private static function applicationOf(object $event): ContainerContract
    {
        $app = property_exists($event, 'app') ? $event->app : null;

        return $app instanceof ContainerContract ? $app : Container::getInstance();
    }
}
