<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Workers;

use Illuminate\Container\Container;

/**
 * Flushes the session and resets the guards in each Octane request's sandbox.
 *
 * Registered by the event's name, so Octane stays optional.
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
        $sandbox = property_exists($event, 'sandbox') ? $event->sandbox : null;

        (new WorkerReset($sandbox instanceof Container ? $sandbox : Container::getInstance()))->forgetMemberState();
    }
}
