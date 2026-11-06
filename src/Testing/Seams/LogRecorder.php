<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Testing\Seams;

use Illuminate\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Log\Events\MessageLogged;
use Illuminate\Log\Logger;
use Illuminate\Log\LogManager;
use PHPUnit\Framework\Assert;

/**
 * Records what Laravel's log is given while a call runs, through the log's
 * `MessageLogged` event, each entry its message and its context read as text,
 * so the gateway kits can look for a code or a destination in it.
 *
 * A context is read as the log's formatters write it, a level at a time: a
 * scalar as itself, an array's keys and values, an exception, and each previous
 * one, by its type, code, message, file and line and its stack trace, with the
 * arguments of each frame (Laravel's channels write the trace of every logged
 * exception), then its JSON form when it gives one, and any other object by its
 * type, then what it gives up: a `JsonSerializable` its JSON form, a
 * `Stringable` its string, an enum its value, and anything else its public
 * properties. An object that refuses one of those by throwing an exception (a
 * `Secret` refuses both its JSON form and its string) is read by its public
 * properties instead, as Monolog falls back to them, and one met again inside
 * itself by its type alone. A context nested deeper than the kit reads is never
 * taken as clean: its entry holds `UNREAD`, which the kits fail.
 *
 * While the call runs, and while an exception it threw is read, PHP records and
 * writes every argument of every frame whole (`zend.exception_ignore_args` off,
 * `zend.exception_string_param_max_len` at its maximum), as its loosest
 * settings have it, so a trace holds whatever it could hold anywhere the
 * gateway runs; both are put back once the call has run or the exception has
 * been read.
 *
 * Before the call runs, an entry of its own is dispatched through the default
 * log channel's event dispatcher; unless it reaches the recorder, it could see
 * nothing the call logs (events are faked, or the log is not Laravel's), and
 * the kit fails rather than pass without looking.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class LogRecorder
{
    /** @var string What an entry holds in place of a context nested deeper than the kit reads. */
    public const string UNREAD = '[a context nested deeper than the gateway kit reads]';

    /** @var string Why the kit fails when it cannot see what is logged. */
    public const string UNREADABLE = 'The gateway kit cannot read the log: an entry dispatched through the default log channel never reached its listener. '
        . 'Run the kit without faking MessageLogged (as Event::fake() does), through Laravel\'s own log manager.';

    /** @var int How deep a logged context is read. */
    private const int DEPTH = 16;

    /** @var array<string, string> PHP's settings for recording and writing every argument of every frame of a stack trace whole, the longest string included. */
    private const array EVERY_ARGUMENT = [
        'zend.exception_ignore_args'          => '0',
        'zend.exception_string_param_max_len' => '1000000',
    ];

    /** @var string The message of the entry the recorder proves it can read the log with. */
    private const string PROBE = 'The gateway kit reads the log.';

    /** @var list<string> What the log was given, oldest first. */
    private array $entries = [];

    /** @var bool Whether the recorder's own entry reached it. */
    private bool $readable = false;

    /**
     * Use `during()`.
     *
     * @param  \Illuminate\Log\Events\MessageLogged  $probe
     */
    private function __construct(

        /** The recorder's own entry. */
        private readonly MessageLogged $probe,
    ) {}

    /**
     * Run the call, and return what the log was given meanwhile, with what the
     * call threw, if anything, failing first when the log cannot be read.
     *
     * @param  \Closure(): mixed  $call
     * @return array{0: list<string>, 1: ?\Throwable}
     */
    public static function during(\Closure $call): array
    {
        $recorder = new self(new MessageLogged('debug', self::PROBE, []));
        $events   = Container::getInstance()->make(Dispatcher::class);

        // What the log is given once the call has run reaches a recording
        // already returned, as a copy, so it is no part of the call's
        $events->listen(MessageLogged::class, static function (MessageLogged $event) use ($recorder): void {
            $recorder->record($event);
        });

        $recorder->assertReadable();

        $settings = self::set(self::EVERY_ARGUMENT);

        try {
            $call();
        } catch (\Throwable $exception) {
            return [$recorder->entries, $exception];
        } finally {
            self::set($settings);
        }

        return [$recorder->entries, null];
    }

    /**
     * An exception the call threw as text, as the worker's exception handler
     * reports it to the log: each in its chain by its type, code, message, file
     * and line and its stack trace, then its JSON form when it gives one.
     *
     * @param  \Throwable  $exception
     * @return string
     */
    public static function exception(\Throwable $exception): string
    {
        // A string argument is cut to its length when its trace is written, not
        // when it is recorded, so the trace is written with every argument
        $settings = self::set(self::EVERY_ARGUMENT);

        try {
            return self::throwable($exception, 0, []);
        } finally {
            self::set($settings);
        }
    }

    /**
     * Set each of PHP's settings, and return what each was before, to be set
     * back the same way.
     *
     * @param  array<string, false|string>  $settings
     * @return array<string, false|string>
     */
    private static function set(array $settings): array
    {
        $before = [];

        foreach ($settings as $name => $value) {
            $before[$name] = ini_set($name, $value);
        }

        return $before;
    }

    /**
     * Record the entry, or note that the recorder's own arrived.
     *
     * @param  \Illuminate\Log\Events\MessageLogged  $event
     * @return void
     */
    private function record(MessageLogged $event): void
    {
        if ($event === $this->probe) {
            $this->readable = true;

            return;
        }

        $this->entries[] = $event->message . "\n" . self::text($event->context, 0, []);
    }

    /**
     * Dispatch the recorder's own entry through the default log channel's event
     * dispatcher, as the channel dispatches every entry it is given, and fail
     * unless it was recorded.
     *
     * @return void
     */
    private function assertReadable(): void
    {
        $logger = Container::getInstance()->make(LogManager::class)->driver();

        if ($logger instanceof Logger) {
            $logger->getEventDispatcher()?->dispatch($this->probe);
        }

        Assert::assertTrue($this->readable, self::UNREADABLE);
    }

    /**
     * A logged value as text, read no deeper than the limit.
     *
     * @param  mixed  $value
     * @param  int  $depth
     * @param  list<int>  $reading
     * @return string
     */
    private static function text(mixed $value, int $depth, array $reading): string
    {
        return match (true) {
            $depth >= self::DEPTH        => self::UNREAD,
            is_scalar($value)            => (string) $value,
            is_array($value)             => self::lines($value, $depth + 1, $reading),
            $value instanceof \Throwable => self::throwable($value, $depth, $reading),
            is_object($value)            => self::object($value, $depth, $reading),
            default                      => get_debug_type($value),
        };
    }

    /**
     * An exception as text, as Laravel's channels write it, then each previous
     * one: its type, code, message, file and line and its stack trace, then its
     * JSON form, as Monolog's normaliser writes it, when it gives one and does
     * not refuse it.
     *
     * @param  \Throwable  $exception
     * @param  int  $depth
     * @param  list<int>  $reading
     * @return string
     */
    private static function throwable(\Throwable $exception, int $depth, array $reading): string
    {
        $lines = [];

        for ($each = $exception; $each !== null; $each = $each->getPrevious()) {

            $lines[] = sprintf('%s(code: %s): %s at %s:%d', get_debug_type($each), $each->getCode(), $each->getMessage(), $each->getFile(), $each->getLine());
            $lines[] = $each->getTraceAsString();

            $json = $each instanceof \JsonSerializable ? self::unlessRefused(static fn (): string => self::text($each->jsonSerialize(), $depth + 1, $reading)) : null;

            if ($json === null) {
                continue;
            }

            $lines[] = $json;
        }

        return implode("\n", $lines);
    }

    /**
     * An object as text: its type, then what it gives up to the log, or its
     * type alone when it is met again inside itself.
     *
     * @param  object  $value
     * @param  int  $depth
     * @param  list<int>  $reading
     * @return string
     */
    private static function object(object $value, int $depth, array $reading): string
    {
        $id = spl_object_id($value);

        if (in_array($id, $reading, true)) {
            return get_debug_type($value);
        }

        $reading[] = $id;

        $read = self::given($value, $depth, $reading) ?? self::lines(get_object_vars($value), $depth + 1, $reading);

        return $read === '' ? get_debug_type($value) : get_debug_type($value) . "\n" . $read;
    }

    /**
     * What an object gives up to the log in a form of its own: its JSON form,
     * its string or its enum value, or `null` when it gives none or refuses the
     * one it has.
     *
     * @param  object  $value
     * @param  int  $depth
     * @param  list<int>  $reading
     * @return ?string
     */
    private static function given(object $value, int $depth, array $reading): ?string
    {
        return match (true) {
            $value instanceof \BackedEnum       => (string) $value->value,
            $value instanceof \UnitEnum         => $value->name,
            $value instanceof \JsonSerializable => self::unlessRefused(static fn (): string => self::text($value->jsonSerialize(), $depth + 1, $reading)),
            $value instanceof \Stringable       => self::unlessRefused(static fn (): string => (string) $value),
            default                             => null,
        };
    }

    /**
     * What the read gives, or `null` when the object it reads refuses it by
     * throwing.
     *
     * @param  \Closure(): string  $read
     * @return ?string
     */
    private static function unlessRefused(\Closure $read): ?string
    {
        try {
            return $read();
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * An array's keys and values as text, a line each.
     *
     * @param  array<array-key, mixed>  $values
     * @param  int  $depth
     * @param  list<int>  $reading
     * @return string
     */
    private static function lines(array $values, int $depth, array $reading): string
    {
        $lines = [];

        foreach ($values as $key => $value) {
            $lines[] = $key . ': ' . self::text($value, $depth, $reading);
        }

        return implode("\n", $lines);
    }
}
