<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Transactions;

use Illuminate\Database\Connection;

/**
 * The work held, by connection, from the moment it is queued inside a
 * transaction until that transaction has committed and the commit has finished
 * (`AfterConnectionCommits`).
 *
 * Each piece is held as it is queued, under a ticket, rather than by a commit
 * callback, so a commit callback queued before it that fails, which stops
 * Laravel running the rest, cannot keep it from being held; a rollback of the
 * transaction it was queued in drops it by its ticket. What is held for a
 * connection is released all at once, in the order it was held, each piece
 * taken off before any runs, so work that commits a transaction of its own
 * releases nothing twice; the first failure is rethrown once the rest have run.
 *
 * It is bound scoped, under this package's own key for scoped adapters, so it
 * holds one request's or one job's work alone, and the worker reset forgets it
 * (IAM-8.1), once the end of the unit of work has released what it could
 * (`AfterConnectionCommits::settle()`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CommittedWork
{
    /** @var array<string, array<int, \Closure(): void>> The work held, by the name of the connection whose commit releases it, each piece under its ticket. */
    private array $held = [];

    /** @var array<string, \Illuminate\Database\Connection> The connections work is held for, by their names. */
    private array $connections = [];

    /** @var int The ticket the next piece is held under. */
    private int $next = 0;

    /**
     * Hold the work until the connection's transaction has committed, and
     * answer the ticket it is held under.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \Closure(): void  $work
     * @return int
     */
    public function hold(Connection $connection, \Closure $work): int
    {
        $name   = self::nameOf($connection);
        $ticket = $this->next++;

        $this->held[$name][$ticket] = $work;
        $this->connections[$name]   = $connection;

        return $ticket;
    }

    /**
     * Drop the piece held under the ticket, as the transaction it was queued in
     * rolls back; a piece already released or dropped is left as it is.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  int  $ticket
     * @return void
     */
    public function drop(Connection $connection, int $ticket): void
    {
        $name = self::nameOf($connection);
        $held = $this->held[$name] ?? [];

        unset($held[$ticket]);

        if ($held !== []) {
            $this->held[$name] = $held;

            return;
        }

        $this->forget($name);
    }

    /**
     * Run the work held for the connection, in the order it was held, and
     * rethrow the first failure once the rest have run.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return void
     *
     * @throws \Throwable
     */
    public function release(Connection $connection): void
    {
        $name = self::nameOf($connection);
        $work = $this->held[$name] ?? [];

        $this->forget($name);

        $failure = null;

        foreach ($work as $piece) {

            try {
                $piece();
            } catch (\Throwable $exception) {
                $failure ??= $exception;
            }
        }

        if ($failure !== null) {
            throw $failure;
        }
    }

    /**
     * The connections work is held for.
     *
     * @return list<\Illuminate\Database\Connection>
     */
    public function connections(): array
    {
        return array_values($this->connections);
    }

    /**
     * Forget what is held for the connection of the name.
     *
     * @param  string  $name
     * @return void
     */
    private function forget(string $name): void
    {
        unset($this->held[$name], $this->connections[$name]);
    }

    /**
     * The name the connection's work is held under: its own, or an empty one
     * for a connection Laravel knows by none.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return string
     */
    private static function nameOf(Connection $connection): string
    {
        return (string) $connection->getName();
    }
}
