<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Provisioning;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Traits\ForwardsCalls;

/**
 * Tells whether an identity a provisioner answers was inserted by that very
 * call (IAM-7.1): the provisioner is asked with every Eloquent model's
 * `created` event witnessed, and its answer counts only when it is one of the
 * very instances inserted while it ran.
 *
 * Eloquent dispatches a model's insertion as its `created` event of its own
 * when the model declares one (`$dispatchesEvents['created']`), built around
 * the model, and as the `eloquent.created: <class>` event unless a listener of
 * its own event answered a value, which skips the second. Both are witnessed:
 * the model's own `created` event, of exactly the class it declares, vouches
 * for each model of that class it carries in any of its properties, so an event
 * of its own that keeps the model it was built with is enough. One that keeps
 * no model vouches for none, and with a listener answering a value no insertion
 * of the model is witnessed at all.
 *
 * A model's `wasRecentlyCreated` stays set on its instance for as long as the
 * instance lives, so a provisioner that kept an identity inserted earlier (by a
 * previous call, or anywhere else in the request) could answer it again and
 * pass a check of the flag alone. Witnessing the insertions of the call closes
 * that: an instance inserted before the call, a fresh instance of a row
 * inserted during it, a model found by an attribute, and a model inserted with
 * its events off (`createQuietly()`, `saveQuietly()`, `withoutEvents()`) are
 * none of them, and are refused, as is any answer while Eloquent has no event
 * dispatcher to witness through.
 *
 * It stands in for Eloquent's event dispatcher only while the provisioner runs
 * and puts the one it found back however the call ends; everything it is asked
 * goes on to that dispatcher unchanged, so every listener and observer of the
 * application's sees what it would have seen. It keeps nothing once the call
 * returns (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class InsertionWitness implements Dispatcher
{
    use ForwardsCalls;

    /** @var string The prefix of the event Eloquent dispatches once a model is inserted. */
    private const string CREATED = 'eloquent.created: ';

    /** @var list<\Illuminate\Database\Eloquent\Model> Every model inserted while the call ran, the very instances. */
    private array $inserted = [];

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Events\Dispatcher  $events
     */
    private function __construct(

        /** Eloquent's own dispatcher, which everything goes on to. */
        private readonly Dispatcher $events,
    ) {}

    /**
     * Hand any other call to Eloquent's dispatcher.
     *
     * @param  string  $method
     * @param  array<array-key, mixed>  $parameters
     * @return mixed
     */
    public function __call(string $method, array $parameters): mixed
    {
        return $this->forwardDecoratedCallTo($this->events, $method, $parameters);
    }

    /**
     * Run the call with every model insertion witnessed, and answer what it
     * answered, with whether that is an Eloquent model, stored, the very
     * instance the call inserted.
     *
     * @template TAnswer of object
     *
     * @param  \Closure(): TAnswer  $call
     * @return array{0: TAnswer, 1: bool}
     */
    public static function witness(\Closure $call): array
    {
        $events = Model::getEventDispatcher();

        if ($events === null) {
            return [$call(), false];
        }

        $witness = new self($events);

        Model::setEventDispatcher($witness);

        try {
            $answer = $call();
        } finally {
            Model::setEventDispatcher($events);
        }

        return [$answer, $witness->inserted($answer)];
    }

    /**
     * Register the listener with Eloquent's dispatcher, as given: a model
     * booting while the call runs registers listeners the contract does not
     * name but Eloquent's dispatcher takes, such as a queued closure or an
     * invokable listener.
     *
     * @param  mixed  $events
     * @param  mixed  $listener
     * @return void
     */
    #[\Override]
    public function listen(mixed $events, mixed $listener = null): void
    {
        $this->forwardDecoratedCallTo($this->events, 'listen', [$events, $listener]);
    }

    /**
     * Whether Eloquent's dispatcher has listeners of the event.
     *
     * @param  string  $eventName
     * @return bool
     */
    #[\Override]
    public function hasListeners(mixed $eventName): bool
    {
        return $this->events->hasListeners($eventName);
    }

    /**
     * Register the subscriber with Eloquent's dispatcher.
     *
     * @param  object|string  $subscriber
     * @return void
     */
    #[\Override]
    public function subscribe(mixed $subscriber): void
    {
        $this->events->subscribe($subscriber);
    }

    /**
     * Dispatch the event through Eloquent's dispatcher until a listener
     * answers.
     *
     * @param  object|string  $event
     * @param  mixed  $payload
     * @return mixed
     */
    #[\Override]
    public function until(mixed $event, mixed $payload = []): mixed
    {
        return $this->events->until($event, $payload);
    }

    /**
     * Witness the model a `created` event carries, Eloquent's or the model's
     * own, and dispatch the event through Eloquent's dispatcher, as given: an
     * event that is neither a name nor an object vouches for nothing, and still
     * goes on.
     *
     * @param  mixed  $event
     * @param  mixed  $payload
     * @param  mixed  $halt
     * @return ($halt is true ? mixed : array<array-key, mixed>|null)
     */
    #[\Override]
    public function dispatch(mixed $event, mixed $payload = [], mixed $halt = false): mixed
    {
        array_push($this->inserted, ...self::carried($event, $payload));

        return $this->forwardDecoratedCallTo($this->events, 'dispatch', [$event, $payload, $halt]);
    }

    /**
     * Push the event onto Eloquent's dispatcher.
     *
     * @param  string  $event
     * @param  array<array-key, mixed>  $payload
     * @return void
     */
    #[\Override]
    public function push(mixed $event, mixed $payload = []): void
    {
        $this->events->push($event, $payload);
    }

    /**
     * Flush the event pushed onto Eloquent's dispatcher.
     *
     * @param  string  $event
     * @return void
     */
    #[\Override]
    public function flush(mixed $event): void
    {
        $this->events->flush($event);
    }

    /**
     * Forget the event's listeners on Eloquent's dispatcher.
     *
     * @param  string  $event
     * @return void
     */
    #[\Override]
    public function forget(mixed $event): void
    {
        $this->events->forget($event);
    }

    /**
     * Forget every event pushed onto Eloquent's dispatcher.
     *
     * @return void
     */
    #[\Override]
    public function forgetPushed(): void
    {
        $this->events->forgetPushed();
    }

    /**
     * The models an event announces the insertion of: the model Eloquent's
     * `created` event names as its payload, or each model the event carries
     * whose own `created` event is exactly the event's class.
     *
     * @param  mixed  $event
     * @param  mixed  $payload
     * @return list<\Illuminate\Database\Eloquent\Model>
     */
    private static function carried(mixed $event, mixed $payload): array
    {
        if (is_string($event)) {
            return str_starts_with($event, self::CREATED) && $payload instanceof Model ? [$payload] : [];
        }

        if (!is_object($event)) {
            return [];
        }

        $announces = static fn (mixed $value): bool => $value instanceof Model && ($value->dispatchesEvents()['created'] ?? null) === $event::class;

        return array_values(array_filter((array) $event, $announces));
    }

    /**
     * Whether the answer is an Eloquent model, stored, and the very instance
     * inserted while the call ran.
     *
     * @param  object  $answer
     * @return bool
     */
    private function inserted(object $answer): bool
    {
        return $answer instanceof Model && $answer->exists && $answer->wasRecentlyCreated && in_array($answer, $this->inserted, true);
    }
}
