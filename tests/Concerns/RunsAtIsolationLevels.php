<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Support\Facades\DB;

/**
 * Runs an integration test at READ COMMITTED and at REPEATABLE READ on MySQL
 * and PostgreSQL, the two isolation levels an application runs the suite's
 * transactions at, and skips it on SQLite, which has neither; a scenario that
 * must hold on every engine also runs at the connection's own level, SQLite's
 * included (`provideEveryIsolationLevel()`).
 *
 * A transaction the package opens, and may open again when it retries, takes
 * the level the connection's session is set to with `useIsolationLevel()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \Tests\TestCase
 */
trait RunsAtIsolationLevels
{
    /**
     * Rows of `[isolation level]`: PostgreSQL's default and MySQL's default.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideIsolationLevels(): iterable
    {
        yield 'read committed' => ['read committed'];

        yield 'repeatable read' => ['repeatable read'];
    }

    /**
     * Rows of `[isolation level]` for a scenario that holds on every engine:
     * the connection's own level, which SQLite runs too, then each of the two
     * levels where the engine has them.
     *
     * @return iterable<string, array{0: ?string}>
     */
    public static function provideEveryIsolationLevel(): iterable
    {
        yield 'the connection\'s own level' => [null];

        yield from self::provideIsolationLevels();
    }

    /**
     * Run the test at the isolation level given, skipping it on a connection
     * without isolation levels to choose between, or at the connection's own
     * level when none is given.
     *
     * @param  ?string  $level
     * @param  ?string  $connection
     * @return void
     */
    protected static function runAtIsolationLevel(?string $level, ?string $connection = null): void
    {
        if ($level === null) {
            return;
        }

        self::requireIsolationLevels($connection);
        self::useIsolationLevel($level, $connection);
    }

    /**
     * Skip the test on a connection without isolation levels to choose between:
     * SQLite serialises every transaction.
     *
     * @param  ?string  $connection
     * @return void
     */
    protected static function requireIsolationLevels(?string $connection = null): void
    {
        if (DB::connection($connection)->getDriverName() !== 'sqlite') {
            return;
        }

        self::markTestSkipped('SQLite has no isolation levels to run at.');
    }

    /**
     * Set the isolation level of every transaction the connection's session
     * opens from now on, a retried one included.
     *
     * @param  string  $level
     * @param  ?string  $connection
     * @return void
     */
    protected static function useIsolationLevel(string $level, ?string $connection = null): void
    {
        $database = DB::connection($connection);

        $database->statement(match ($database->getDriverName()) {
            'pgsql' => 'set session characteristics as transaction isolation level ' . $level,
            default => 'set session transaction isolation level ' . $level,
        });
    }
}
