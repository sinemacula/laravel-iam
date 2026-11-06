<?php

declare(strict_types = 1);

namespace Tests\Feature\Testing;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Log\Events\MessageLogged;
use Illuminate\Log\Logger;
use Illuminate\Log\LogManager;
use Illuminate\Queue\Events\JobProcessing;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;
use Monolog\Logger as Monolog;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Iam\Delivery\Enums\Channel;
use SineMacula\Laravel\Iam\Testing\Seams\LogRecorder;
use Tests\Fixtures\Delivery\RefusingProvider;
use Tests\Fixtures\Testing\Enums\Pure;
use Tests\Fixtures\Testing\Enums\Ranked;
use Tests\Fixtures\Testing\LoggedJson;
use Tests\Fixtures\Testing\LoggedJsonException;
use Tests\Fixtures\Testing\LoggedProperties;
use Tests\Fixtures\Testing\LoggedString;
use Tests\TestCase;

/**
 * Feature tests for recording what Laravel's log is given while a call runs, as
 * the gateway kits read it: each entry is its message and its context as text,
 * an exception and any other object as the log writes it, a stack trace with
 * every argument whole while the call runs, a context nested deeper than the
 * limit read as unread, nothing logged once the call has run is the call's, and
 * a log the recorder cannot read fails it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LogRecorder::class)]
final class LogRecorderTest extends TestCase
{
    /**
     * Each entry is the message, then each key of its context with its value, a
     * line each, nested arrays a level at a time.
     *
     * @return void
     */
    public function testAnEntryIsItsMessageAndItsContext(): void
    {
        [$logged, $thrown] = LogRecorder::during(static function (): void {
            Log::info('Sent', ['to' => 'ada', 'attempt' => 2, 'sent' => true, 'body' => ['text' => 'hello', 'parts' => [1, 2]]]);
            Log::warning('Again');
        });

        self::assertSame(["Sent\nto: ada\nattempt: 2\nsent: 1\nbody: text: hello\nparts: 0: 1\n1: 2", "Again\n"], $logged);
        self::assertNull($thrown);
    }

    /**
     * An exception is read as Laravel's channels write it, then each previous
     * one: its type, code, message, file and line and its stack trace, then its
     * JSON form when it gives one and does not refuse it.
     *
     * @return void
     */
    public function testAnExceptionIsReadAsTheLogWritesIt(): void
    {
        $inner   = new LoggedJsonException('inner', ['to' => 'json-to']);
        $refused = new LoggedJsonException('refused', LoggedJsonException::REFUSE, $inner);
        $outer   = new \RuntimeException('outer', 7, $refused);

        [$logged, $thrown] = LogRecorder::during(static fn () => Log::error('Failed', ['exception' => $outer]));

        self::assertNull($thrown);
        self::assertSame(implode("\n", [
            'Failed',
            'exception: ' . self::header($outer, 'RuntimeException(code: 7): outer'),
            self::wholeTrace($outer),
            self::header($refused, LoggedJsonException::class . '(code: 0): refused'),
            self::wholeTrace($refused),
            self::header($inner, LoggedJsonException::class . '(code: 0): inner'),
            self::wholeTrace($inner),
            'to: json-to',
        ]), $logged[0]);
        self::assertSame(implode("\n", array_slice(explode("\n", $logged[0]), 1)), 'exception: ' . LogRecorder::exception($outer));
    }

    /**
     * While the call runs, a stack trace holds every argument of every frame
     * whole, whatever PHP was set to record, in what is logged and in what the
     * call throws; once it has run, either way, the settings are put back.
     *
     * @return void
     */
    public function testATraceHoldsEveryArgumentWholeWhileTheCallRuns(): void
    {
        $ignored = ini_set('zend.exception_ignore_args', '1');
        $length  = ini_set('zend.exception_string_param_max_len', '15');

        try {
            [$logged, $thrown] = LogRecorder::during(static function (): void {
                try {
                    RefusingProvider::send('a logged argument longer than the setting allows');
                } catch (\RuntimeException $exception) {
                    Log::warning('Failed', ['exception' => $exception]);
                }

                RefusingProvider::send('a thrown argument longer than the setting allows');
            });

            self::assertInstanceOf(\RuntimeException::class, $thrown);
            self::assertStringContainsString(RefusingProvider::class . '::send(\'a logged argument longer than the setting allows\')', $logged[0]);
            self::assertStringContainsString(RefusingProvider::class . '::send(\'a thrown argument longer than the setting allows\')', LogRecorder::exception($thrown));
            self::assertSame(['1', '15'], [ini_get('zend.exception_ignore_args'), ini_get('zend.exception_string_param_max_len')]);

            LogRecorder::during(static fn () => null);

            self::assertSame(['1', '15'], [ini_get('zend.exception_ignore_args'), ini_get('zend.exception_string_param_max_len')]);
        } finally {
            ini_set('zend.exception_ignore_args', $ignored);
            ini_set('zend.exception_string_param_max_len', $length);
        }
    }

    /**
     * An exception the call threw is read to the depth the kit reads, its JSON
     * form one level below it: read at the last level, unread one deeper.
     *
     * @return void
     */
    public function testAThrownExceptionIsReadToTheDepthTheKitReads(): void
    {
        $within = 'bottom';
        $beyond = ['bottom'];

        for ($level = 0; $level < 14; $level++) {
            $within = [$within];
            $beyond = [$beyond];
        }

        $read   = LogRecorder::exception(new LoggedJsonException('Refused', $within));
        $unread = LogRecorder::exception(new LoggedJsonException('Refused', $beyond));

        self::assertStringEndsWith('0: bottom', $read);
        self::assertStringNotContainsString(LogRecorder::UNREAD, $read);
        self::assertStringEndsWith('0: ' . LogRecorder::UNREAD, $unread);
        self::assertStringNotContainsString('bottom', $unread);
    }

    /**
     * An enum is read as its value or name, and any other object by its type,
     * then as the log writes it: its JSON form, its string or its public
     * properties; one that refuses its JSON form or its string by its public
     * properties instead, and one met again inside itself by its type alone.
     *
     * @return void
     */
    public function testAnObjectIsReadAsTheLogWritesIt(): void
    {
        $looped = new \stdClass;

        $looped->self = $looped;

        // Dispatched as the log dispatches an entry once it is written, since
        // Monolog cannot write an object that refuses to be encoded
        [$logged, $thrown] = LogRecorder::during(static fn () => Event::dispatch(new MessageLogged('error', 'Failed', [
            'at'       => new \ArrayObject,
            'none'     => null,
            'json'     => new LoggedJson(['to' => 'json-to'], 'json-public'),
            'string'   => new LoggedString('string-body', 'string-public'),
            'plain'    => new LoggedProperties('public-value'),
            'refuses'  => new LoggedJson(LoggedJson::REFUSE, 'json-refused'),
            'unstrung' => new LoggedString(LoggedString::REFUSE, 'string-refused'),
            'secret'   => new Secret('482915'),
            'backed'   => Channel::SMS,
            'unit'     => Pure::ONE,
            'ranked'   => Ranked::FIRST,
            'looped'   => $looped,
        ])));

        self::assertNull($thrown, (string) $thrown?->getMessage());
        self::assertSame(implode("\n", [
            'Failed',
            'at: ArrayObject',
            'none: null',
            'json: ' . LoggedJson::class,
            'to: json-to',
            'string: ' . LoggedString::class,
            'string-body',
            'plain: ' . LoggedProperties::class,
            'public: public-value',
            'refuses: ' . LoggedJson::class,
            'public: json-refused',
            'unstrung: ' . LoggedString::class,
            'public: string-refused',
            'secret: ' . Secret::class,
            'backed: ' . Channel::class,
            'sms',
            'unit: ' . Pure::class,
            'ONE',
            'ranked: ' . Ranked::class,
            '1',
            'looped: stdClass',
            'self: stdClass',
        ]), $logged[0]);
    }

    /**
     * A context nested deeper than the kit reads is never taken as clean: what
     * lies beyond the limit is read as unread, whether arrays or objects hold
     * it.
     *
     * @return void
     */
    public function testAContextNestedTooDeepIsReadAsUnread(): void
    {
        $shallow = ['l0' => 'bottom'];
        $nested  = new LoggedProperties('bottom');

        for ($level = 1; $level < 15; $level++) {
            $shallow = ['l' . $level => $shallow];
        }

        for ($level = 1; $level < 16; $level++) {
            $nested = new LoggedProperties($nested);
        }

        $deep = ['l15' => $shallow];

        [$logged] = LogRecorder::during(static function () use ($deep, $shallow, $nested): void {
            Log::info('Deep', $deep);
            Log::info('Nested', ['object' => $nested]);
            Log::info('Shallow', $shallow);
        });

        self::assertStringEndsWith('l0: ' . LogRecorder::UNREAD, $logged[0]);
        self::assertStringNotContainsString('bottom', $logged[0]);
        self::assertStringEndsWith(LogRecorder::UNREAD, $logged[1]);
        self::assertStringNotContainsString(LogRecorder::UNREAD, $logged[2]);
        self::assertStringEndsWith('l0: bottom', $logged[2]);
    }

    /**
     * Rows of `[object holding the bottom value]`: one read by its JSON form,
     * one by its public properties, and one by them once it refuses its JSON
     * form.
     *
     * @return iterable<string, array{0: \Closure(): object}>
     */
    public static function provideObjectsAtTheLimit(): iterable
    {
        yield 'a JSON form' => [static fn (): object => new LoggedJson('bottom')];

        yield 'public properties' => [static fn (): object => new LoggedProperties('bottom')];

        yield 'public properties of a refused JSON form' => [static fn (): object => new LoggedJson(LoggedJson::REFUSE, 'bottom')];
    }

    /**
     * What an object gives up is read one level below the object: read at the
     * last level the kit reads, unread one level deeper.
     *
     * @param  \Closure(): object  $object
     * @return void
     */
    #[DataProvider('provideObjectsAtTheLimit')]
    public function testWhatAnObjectGivesUpIsReadOneLevelBelowIt(\Closure $object): void
    {
        $within = $object();
        $beyond = [$object()];

        for ($level = 0; $level < 13; $level++) {
            $within = [$within];
            $beyond = [$beyond];
        }

        [$logged] = LogRecorder::during(static function () use ($within, $beyond): void {
            Event::dispatch(new MessageLogged('info', 'Within', ['object' => $within]));
            Event::dispatch(new MessageLogged('info', 'Beyond', ['object' => $beyond]));
        });

        self::assertStringEndsWith('bottom', $logged[0]);
        self::assertStringNotContainsString(LogRecorder::UNREAD, $logged[0]);
        self::assertStringEndsWith(LogRecorder::UNREAD, $logged[1]);
        self::assertStringNotContainsString('bottom', $logged[1]);
    }

    /**
     * A default channel whose logger dispatches no events cannot be read, so
     * the recorder fails.
     *
     * @return void
     */
    public function testTheRecorderFailsWhenTheDefaultChannelDispatchesNoEvents(): void
    {
        $app = $this->app ?? self::fail('The application has not booted.');

        $app->instance(LogManager::class, new class ($app) extends LogManager {
            /**
             * Laravel's logger, with no event dispatcher.
             *
             * @param  mixed  $driver
             * @return \Psr\Log\LoggerInterface
             */
            #[\Override]
            public function driver(mixed $driver = null): LoggerInterface
            {
                return new Logger(new Monolog('silent'));
            }
        });

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage(LogRecorder::UNREADABLE);

        LogRecorder::during(static fn () => null);
    }

    /**
     * The recorder fails, rather than record nothing, when the log's entries
     * cannot reach it: events are faked once the log channel is resolved again,
     * or the default channel is not Laravel's logger.
     *
     * @return void
     */
    public function testTheRecorderFailsWhenItCannotReadTheLog(): void
    {
        Event::fake();
        Log::forgetChannel('null');

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage(LogRecorder::UNREADABLE);

        LogRecorder::during(static fn () => self::fail('The call must not run once the log cannot be read.'));
    }

    /**
     * A default channel that is not Laravel's logger dispatches no event the
     * recorder could read, so it fails.
     *
     * @return void
     */
    public function testTheRecorderFailsWhenTheDefaultChannelIsNotLaravels(): void
    {
        $app = $this->app ?? self::fail('The application has not booted.');

        $app->instance(LogManager::class, new class ($app) extends LogManager {
            /**
             * A logger outside Laravel's own.
             *
             * @param  mixed  $driver
             * @return \Psr\Log\LoggerInterface
             */
            #[\Override]
            public function driver(mixed $driver = null): LoggerInterface
            {
                return new NullLogger;
            }
        });

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage(LogRecorder::UNREADABLE);

        LogRecorder::during(static fn () => null);
    }

    /**
     * The recorder's own entry is never recorded as the call's, and it reads
     * the log while only some events are faked.
     *
     * @return void
     */
    public function testTheRecordersOwnEntryIsNotTheCalls(): void
    {
        Event::fake([JobProcessing::class]);
        Log::forgetChannel('null');

        [$logged, $thrown] = LogRecorder::during(static fn () => Log::info('Only'));

        self::assertSame(["Only\n"], $logged);
        self::assertNull($thrown);
    }

    /**
     * What the call throws is returned with what was logged before it, and what
     * the log is given after the call has run is not the call's.
     *
     * @return void
     */
    public function testWhatTheCallThrowsIsReturnedAndLaterEntriesAreNotRecorded(): void
    {
        $failure = new \LogicException('broken');

        [$logged, $thrown] = LogRecorder::during(static function () use ($failure): void {
            Log::info('During', ['step' => 1]);

            throw $failure;
        });

        Log::info('After');

        self::assertSame(["During\nstep: 1"], $logged);
        self::assertSame($failure, $thrown);
    }

    /**
     * Send the log nowhere: what is logged is read from its event.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        $app->make('config')->set('logging.default', 'null');
    }

    /**
     * The first line the recorder reads an exception by.
     *
     * @param  \Throwable  $exception
     * @param  string  $typeCodeAndMessage
     * @return string
     */
    private static function header(\Throwable $exception, string $typeCodeAndMessage): string
    {
        return sprintf('%s at %s:%d', $typeCodeAndMessage, $exception->getFile(), $exception->getLine());
    }

    /**
     * The exception's stack trace, every string argument written whole.
     *
     * @param  \Throwable  $exception
     * @return string
     */
    private static function wholeTrace(\Throwable $exception): string
    {
        $length = ini_set('zend.exception_string_param_max_len', '1000000');

        try {
            return $exception->getTraceAsString();
        } finally {
            ini_set('zend.exception_string_param_max_len', $length);
        }
    }
}
