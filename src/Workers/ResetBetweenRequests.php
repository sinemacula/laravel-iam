<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Workers;

use Illuminate\Container\Container;
use Illuminate\Contracts\Container\Container as ContainerContract;

/**
 * Starts every Octane request with every member's request state flushed.
 *
 * It listens to `Laravel\Octane\Events\RequestReceived` by name, so Octane
 * stays optional. Octane dispatches the event once the request's sandbox is the
 * current application, so the reset reaches the sandbox; the event's own
 * `sandbox` is preferred where it carries one.
 *
 * The scoped instances are left where they are. Every sandbox is a fresh clone
 * of the worker's application, whose scoped instances Octane forgets once each
 * operation ends and this package forgets as the worker starts, so none is left
 * from the last request; and by the time this listener runs, Octane's
 * listeners, the application's own among them, have already filled some for
 * this request (its `Context`, its deferred callbacks), which a second flush
 * would discard.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ResetBetweenRequests
{
    /** @var string The Octane event the listener is registered for. */
    public const string EVENT = 'Laravel\Octane\Events\RequestReceived';

    /**
     * Handle Octane's `RequestReceived` event.
     *
     * @param  object  $event
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function __invoke(object $event): void
    {
        (new WorkerReset(self::sandboxOf($event)))->forgetMemberState();
    }

    /**
     * Return the application the request runs in: the event's `sandbox` when it
     * is a container, otherwise the current one.
     *
     * @param  object  $event
     * @return \Illuminate\Contracts\Container\Container
     */
    private static function sandboxOf(object $event): ContainerContract
    {
        $sandbox = property_exists($event, 'sandbox') ? $event->sandbox : null;

        return $sandbox instanceof ContainerContract ? $sandbox : Container::getInstance();
    }
}
