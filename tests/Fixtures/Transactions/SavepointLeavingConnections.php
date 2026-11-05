<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Transactions;

use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\MySqlConnection;
use Illuminate\Database\PostgresConnection;
use Illuminate\Database\SQLiteConnection;
use Tests\Fixtures\Transactions\Concerns\LeavesTheSavepointAfterAConcurrencyFailure;

/**
 * Replaces a connection with one of the same driver, on the same PDO, that
 * leaves a nested transaction's savepoint in place after a concurrency failure,
 * as Laravel before 13.40 does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SavepointLeavingConnections
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Make the named connection one that leaves the savepoint, keeping the PDO
     * it is open on, so an in-memory database and the tables already created on
     * it survive the swap.
     *
     * @param  \Illuminate\Database\DatabaseManager  $database
     * @param  string  $name
     * @return void
     */
    public static function replace(DatabaseManager $database, string $name): void
    {
        $current = $database->connection($name);
        $pdo     = $current->getPdo();

        $database->extend($name, static fn (): Connection => self::leavingTheSavepoint($current, $pdo));
        $database->purge($name);
    }

    /**
     * Return a connection of the same driver as the given one, on the given
     * PDO, that leaves the savepoint.
     *
     * @param  \Illuminate\Database\Connection  $current
     * @param  \PDO  $pdo
     * @return \Illuminate\Database\Connection
     */
    private static function leavingTheSavepoint(Connection $current, \PDO $pdo): Connection
    {
        $arguments = [$pdo, $current->getDatabaseName(), $current->getTablePrefix(), (array) $current->getConfig()];

        return match (true) {
            $current instanceof MySqlConnection => new class (...$arguments) extends MySqlConnection {
                use LeavesTheSavepointAfterAConcurrencyFailure;
            },
            $current instanceof PostgresConnection => new class (...$arguments) extends PostgresConnection {
                use LeavesTheSavepointAfterAConcurrencyFailure;
            },
            default => new class (...$arguments) extends SQLiteConnection {
                use LeavesTheSavepointAfterAConcurrencyFailure;
            },
        };
    }
}
