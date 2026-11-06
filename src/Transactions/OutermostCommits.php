<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Transactions;

use Illuminate\Database\Connection;
use Illuminate\Database\Events\TransactionCommitting;

/**
 * How many outermost commits each connection has begun in this request or job,
 * counted from Laravel's `TransactionCommitting` event, which a connection
 * fires just before it commits its outermost transaction, and never for a
 * savepoint (IAM-11.2).
 *
 * A retry that this package does not open the transaction for (a standalone
 * `link`, whose transaction SSO opens and commits itself) reads the count
 * before each attempt and again after its failure: when the count moved, the
 * attempt reached its commit, and the failure came from the commit itself or
 * from what ran once it committed (an after-commit callback, a listener of an
 * event dispatched after the commit), so the attempt is never run again, since
 * that would apply its change twice. A commit that itself failed is counted
 * too, which errs on the side of not retrying: the caller retries the request.
 *
 * It is bound scoped, under this package's own key for scoped adapters, so it
 * counts one request's or one job's commits alone, and the worker reset forgets
 * it (IAM-8.1); the listener resolves it from the container on each event.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class OutermostCommits
{
    /** @var array<string, int> How many outermost commits each connection has begun, by its name. */
    private array $begun = [];

    /**
     * Count the outermost commit the connection is about to make.
     *
     * @param  \Illuminate\Database\Events\TransactionCommitting  $event
     * @return void
     */
    public function committing(TransactionCommitting $event): void
    {
        $this->begun[self::nameOf($event->connection)] = $this->count($event->connection) + 1;
    }

    /**
     * How many outermost commits the connection has begun, counted by its name,
     * so a connection Laravel resolves again under the same name continues its
     * count.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return int
     */
    public function count(Connection $connection): int
    {
        return $this->begun[self::nameOf($connection)] ?? 0;
    }

    /**
     * The name the connection's commits are counted under: its own, or an empty
     * one for a connection Laravel knows by none.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return string
     */
    private static function nameOf(Connection $connection): string
    {
        return (string) $connection->getName();
    }
}
