<?php

declare(strict_types = 1);

namespace Tests\Concerns;

/**
 * Runs a check's closures, as `iam:check` and SSO's checker run them, and
 * collects what each found: the message of every closure that threw, and every
 * note a closure returned.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait RunsChecks
{
    /**
     * The message of every closure that threw, in order.
     *
     * @param  list<\Closure(): mixed>  $checks
     * @return list<string>
     *
     * @phpstan-impure
     */
    protected static function problems(array $checks): array
    {
        return self::findings($checks)[0];
    }

    /**
     * Every note a closure returned, in order.
     *
     * @param  list<\Closure(): mixed>  $checks
     * @return list<string>
     *
     * @phpstan-impure
     */
    protected static function notes(array $checks): array
    {
        return self::findings($checks)[1];
    }

    /**
     * Run every closure, collecting the messages of those that threw and the
     * notes of those that returned one.
     *
     * @param  list<\Closure(): mixed>  $checks
     * @return array{list<string>, list<string>}
     *
     * @phpstan-impure
     */
    private static function findings(array $checks): array
    {
        $problems = [];
        $notes    = [];

        foreach ($checks as $check) {

            try {
                $note = $check();
            } catch (\Throwable $exception) {
                $problems[] = $exception->getMessage();

                continue;
            }

            if (!is_string($note)) {
                continue;
            }

            $notes[] = $note;
        }

        return [$problems, $notes];
    }
}
