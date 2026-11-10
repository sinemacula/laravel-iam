<?php

declare(strict_types = 1);

namespace Tests\Integration\Provisioning;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Iam\Provisioning\InsertionWitness;
use Tests\Concerns\MigratesMembers;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Provisioning\AnnouncedPerson;
use Tests\Fixtures\Provisioning\PersonAnnounced;
use Tests\TestCase;

/**
 * Integration tests for how the provisioning listener tells an identity the
 * provisioner inserted during its call (IAM-7.1): only the very instance whose
 * insertion the call made is witnessed, never one inserted before the call and
 * kept, a fresh instance of a row inserted during it, one found, one never
 * stored, one deleted again, one inserted with its model events off, nor any
 * answer while Eloquent has no dispatcher; a model announcing its insertion
 * with an event of its own is witnessed through that event alone; Eloquent's
 * own dispatcher is put back however the call ends; and every call the witness
 * takes goes on to that dispatcher unchanged.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(InsertionWitness::class)]
final class InsertionWitnessTest extends TestCase
{
    use MigratesMembers;

    /**
     * A person inserted during the call, the very instance answered, is
     * witnessed, and the application's listeners of the insertion still hear
     * it.
     *
     * @return void
     */
    public function testAnInstanceInsertedDuringTheCallIsWitnessed(): void
    {
        $heard = [];

        Person::created(static function (Person $person) use (&$heard): void {
            $heard[] = $person;
        });

        [$person, $inserted] = InsertionWitness::witness(static fn (): Person => self::insert('new@people.test'));

        self::assertTrue($inserted);
        self::assertSame([$person], $heard);
    }

    /**
     * An answer is not witnessed unless the call inserted that very instance:
     * one inserted before and kept, a fresh instance of a row the call
     * inserted, one found, one never stored, one deleted again, one inserted
     * with its model events off, and anything that is no model.
     *
     * @return void
     */
    public function testNoOtherAnswerIsWitnessed(): void
    {
        $kept = self::insert('kept@people.test');

        $answers = [
            'kept'      => static fn (): Person => $kept,
            'fresh'     => static fn (): Person => self::insert('fresh@people.test')->fresh() ?? self::fail('No row.'),
            'found'     => static fn (): Person => Person::query()->findOrFail($kept->id),
            'unsaved'   => static fn (): Person => new Person(['name' => 'Unsaved', 'email' => 'unsaved@people.test']),
            'deleted'   => static fn (): Person => self::deleted(self::insert('deleted@people.test')),
            'forgotten' => static fn (): Person => self::forgotten(self::insert('forgotten@people.test')),
            'quiet'     => static fn (): Person => Person::query()->createQuietly(['name' => 'Quiet', 'email' => 'quiet@people.test']),
            'no model'  => static fn (): object => new \stdClass,
        ];

        foreach ($answers as $case => $answer) {
            self::assertFalse(InsertionWitness::witness($answer)[1], $case);
        }
    }

    /**
     * A model inserted during the call other than the one answered does not
     * vouch for it, nor does another of the model's events.
     *
     * @return void
     */
    public function testOnlyTheInsertionOfTheAnswerVouchesForIt(): void
    {
        $kept = self::insert('kept@people.test');

        [, $inserted] = InsertionWitness::witness(static function () use ($kept): Person {
            self::insert('other@people.test');

            $kept->update(['name' => 'Updated']);
            $kept->save();

            Model::getEventDispatcher()?->dispatch('eloquent.updated: ' . Person::class, $kept);
            Model::getEventDispatcher()?->dispatch(new \stdClass);
            Model::getEventDispatcher()?->dispatch('eloquent.created: ' . Person::class, [$kept]);

            return $kept;
        });

        self::assertFalse($inserted);
    }

    /**
     * A model that announces its insertion with an event of its own, whose
     * listener answers a value so Eloquent skips its `eloquent.created` event,
     * is still witnessed through the event of its own, which carries it.
     *
     * @return void
     */
    public function testAnInsertionAnnouncedByTheModelsOwnEventIsWitnessed(): void
    {
        $heard = [];

        Event::listen(PersonAnnounced::class, static fn (): bool => true);
        Event::listen('eloquent.created: ' . AnnouncedPerson::class, static function (AnnouncedPerson $person) use (&$heard): void {
            $heard[] = $person;
        });

        $insert = static fn (): AnnouncedPerson => AnnouncedPerson::query()->create(['name' => 'Announced', 'email' => 'announced@people.test']);

        [$person, $inserted] = InsertionWitness::witness($insert);

        self::assertTrue($person->exists);
        self::assertSame([], $heard);
        self::assertTrue($inserted);
    }

    /**
     * Only a model's own `created` event, of exactly the class it declares,
     * vouches for the model it carries: another event carrying a model kept
     * from before the call does not, nor does the event carrying a model that
     * declares no event of its own.
     *
     * @return void
     */
    public function testOnlyTheModelsOwnCreatedEventVouchesForIt(): void
    {
        $announced = AnnouncedPerson::query()->create(['name' => 'Kept', 'email' => 'kept@people.test']);
        $plain     = self::insert('plain@people.test');

        [, $inserted] = InsertionWitness::witness(static function () use ($announced): AnnouncedPerson {
            $decoy         = new \stdClass;
            $decoy->person = $announced;

            Model::getEventDispatcher()?->dispatch($decoy);

            return $announced;
        });

        self::assertFalse($inserted);

        [, $inserted] = InsertionWitness::witness(static function () use ($plain): Person {
            Model::getEventDispatcher()?->dispatch(new PersonAnnounced($plain));

            return $plain;
        });

        self::assertFalse($inserted);
    }

    /**
     * An event that is neither a name nor an object, carrying the very model
     * the call answers, vouches for nothing, and still goes on to Eloquent's
     * dispatcher.
     *
     * @return void
     */
    public function testAnEventThatIsNeitherANameNorAnObjectVouchesForNothing(): void
    {
        $kept     = AnnouncedPerson::query()->create(['name' => 'Kept', 'email' => 'kept@people.test']);
        $events   = self::recording();
        $previous = Model::getEventDispatcher();

        Model::setEventDispatcher($events);

        try {
            [, $inserted] = InsertionWitness::witness(static function () use ($kept): AnnouncedPerson {
                $witness = Model::getEventDispatcher();

                self::assertInstanceOf(InsertionWitness::class, $witness);

                $witness->dispatch([$kept]);

                return $kept;
            });
        } finally {
            Model::setEventDispatcher($previous ?? self::fail('Eloquent had no dispatcher.'));
        }

        self::assertFalse($inserted);
        self::assertSame([['dispatch', [[$kept], [], false]]], $events->calls);
    }

    /**
     * Eloquent's dispatcher is put back once the call returns and once it
     * throws, and the witness stands in for it only while the call runs.
     *
     * @return void
     *
     * @throws \RuntimeException
     */
    public function testEloquentsDispatcherIsPutBackHoweverTheCallEnds(): void
    {
        $events = Model::getEventDispatcher();
        $during = null;

        InsertionWitness::witness(static function () use (&$during): object {
            $during = Model::getEventDispatcher();

            return new \stdClass;
        });

        self::assertInstanceOf(InsertionWitness::class, $during);
        self::assertSame($events, Model::getEventDispatcher());

        $failure = new \RuntimeException('The provisioner failed.');

        try {
            InsertionWitness::witness(static fn (): object => throw $failure);

            self::fail('Nothing was thrown.');
        } catch (\RuntimeException $thrown) {
            self::assertSame($failure, $thrown);
        }

        self::assertSame($events, Model::getEventDispatcher());
    }

    /**
     * With no dispatcher, Eloquent dispatches no insertion to witness: the call
     * still runs, its answer is not witnessed, and Eloquent is left with none.
     *
     * @return void
     */
    public function testWithoutADispatcherNothingIsWitnessed(): void
    {
        $events = Model::getEventDispatcher();

        Model::unsetEventDispatcher();

        try {
            [$person, $inserted] = InsertionWitness::witness(static fn (): Person => self::insert('new@people.test'));

            self::assertTrue($person->wasRecentlyCreated);
            self::assertFalse($inserted);
            self::assertNull(Model::getEventDispatcher());
        } finally {
            Model::setEventDispatcher($events ?? self::fail('Eloquent had no dispatcher.'));
        }
    }

    /**
     * Every call the witness takes goes on to Eloquent's dispatcher, with its
     * answer: each of the contract's methods and any other.
     *
     * @return void
     */
    public function testEveryCallGoesOnToEloquentsDispatcher(): void
    {
        $events     = self::recording();
        $listener   = static function (): void {};
        $subscriber = new \stdClass;
        $previous   = Model::getEventDispatcher();

        Model::setEventDispatcher($events);

        try {
            InsertionWitness::witness(static function () use ($listener, $subscriber): object {
                $witness = Model::getEventDispatcher();

                self::assertInstanceOf(InsertionWitness::class, $witness);

                $witness->listen('event', $listener);
                $witness->subscribe($subscriber);
                $witness->push('event', ['pushed']);
                $witness->flush('event');
                $witness->forget('event');
                $witness->forgetPushed();

                self::assertTrue($witness->hasListeners('event'));
                self::assertSame(['dispatched'], $witness->dispatch('event', ['payload'], true));
                self::assertSame(['dispatched'], $witness->dispatch('event'));
                self::assertSame('until', $witness->until('event', ['payload']));
                self::assertSame('other', $witness->other('event')); // @phpstan-ignore method.notFound

                return new \stdClass;
            });
        } finally {
            Model::setEventDispatcher($previous ?? self::fail('Eloquent had no dispatcher.'));
        }

        self::assertSame([
            ['listen', ['event', $listener]],
            ['subscribe', [$subscriber]],
            ['push', ['event', ['pushed']]],
            ['flush', ['event']],
            ['forget', ['event']],
            ['forgetPushed', []],
            ['hasListeners', ['event']],
            ['dispatch', ['event', ['payload'], true]],
            ['dispatch', ['event', [], false]],
            ['until', ['event', ['payload']]],
            ['other', ['event']],
        ], $events->calls);
    }

    /**
     * A dispatcher that keeps every call it takes, and answers each.
     *
     * @return \Illuminate\Contracts\Events\Dispatcher&object{calls: list<array{0: string, 1: list<mixed>}>}
     */
    private static function recording(): Dispatcher
    {
        return new class implements Dispatcher {
            /** @var list<array{0: string, 1: list<mixed>}> Every call taken, in order. */
            public array $calls = [];

            /**
             * Keep the listener.
             *
             * @param  mixed  $events
             * @param  mixed  $listener
             * @return void
             */
            #[\Override]
            public function listen(mixed $events, mixed $listener = null): void
            {
                $this->calls[] = ['listen', [$events, $listener]];
            }

            /**
             * Keep the question, and answer that there are listeners.
             *
             * @param  mixed  $eventName
             * @return bool
             */
            #[\Override]
            public function hasListeners(mixed $eventName): bool
            {
                $this->calls[] = ['hasListeners', [$eventName]];

                return true;
            }

            /**
             * Keep the subscriber.
             *
             * @param  mixed  $subscriber
             * @return void
             */
            #[\Override]
            public function subscribe(mixed $subscriber): void
            {
                $this->calls[] = ['subscribe', [$subscriber]];
            }

            /**
             * Keep the dispatch, and answer one listener's answer.
             *
             * @param  mixed  $event
             * @param  mixed  $payload
             * @return mixed
             */
            #[\Override]
            public function until(mixed $event, mixed $payload = []): mixed
            {
                $this->calls[] = ['until', [$event, $payload]];

                return 'until';
            }

            /**
             * Keep the dispatch, and answer the listeners' answers.
             *
             * @param  mixed  $event
             * @param  mixed  $payload
             * @param  mixed  $halt
             * @return ($halt is true ? mixed : array<array-key, mixed>|null)
             */
            #[\Override]
            public function dispatch(mixed $event, mixed $payload = [], mixed $halt = false): mixed
            {
                $this->calls[] = ['dispatch', [$event, $payload, $halt]];

                return ['dispatched'];
            }

            /**
             * Keep the event pushed.
             *
             * @param  mixed  $event
             * @param  mixed  $payload
             * @return void
             */
            #[\Override]
            public function push(mixed $event, mixed $payload = []): void
            {
                $this->calls[] = ['push', [$event, $payload]];
            }

            /**
             * Keep the flush.
             *
             * @param  mixed  $event
             * @return void
             */
            #[\Override]
            public function flush(mixed $event): void
            {
                $this->calls[] = ['flush', [$event]];
            }

            /**
             * Keep the forgetting.
             *
             * @param  mixed  $event
             * @return void
             */
            #[\Override]
            public function forget(mixed $event): void
            {
                $this->calls[] = ['forget', [$event]];
            }

            /**
             * Keep the forgetting of everything pushed.
             *
             * @return void
             */
            #[\Override]
            public function forgetPushed(): void
            {
                $this->calls[] = ['forgetPushed', []];
            }

            /**
             * A method beyond the contract: keep the call, and answer it.
             *
             * @param  string  $event
             * @return string
             */
            public function other(string $event): string
            {
                $this->calls[] = ['other', [$event]];

                return 'other';
            }
        };
    }

    /**
     * Insert a person with the email address given.
     *
     * @param  string  $email
     * @return \Tests\Fixtures\Models\Person
     */
    private static function insert(string $email): Person
    {
        return Person::query()->create(['name' => 'Person', 'email' => $email]);
    }

    /**
     * The person, deleted again.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return \Tests\Fixtures\Models\Person
     */
    private static function deleted(Person $person): Person
    {
        $person->delete();

        return $person;
    }

    /**
     * The person, no longer marked as inserted by the call.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return \Tests\Fixtures\Models\Person
     */
    private static function forgotten(Person $person): Person
    {
        $person->wasRecentlyCreated = false;

        return $person;
    }
}
