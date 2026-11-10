<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Transactions;

use Illuminate\Container\Container;
use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseTransactionRecord;
use Illuminate\Database\DatabaseTransactionsManager;

/**
 * The transactions open on one connection that a callback waiting for their end
 * can be attached to, outermost first.
 *
 * They are those Laravel's transactions manager lets callbacks apply to, so the
 * transaction a testing trait wraps a test in is none, and of those only the
 * ones the connection still has open, since inside the rollback of the
 * outermost the manager still lists it. A callback that must run whenever any
 * of them rolls back is attached to each, not only the innermost: not every
 * version of Laravel tells a savepoint that has committed of its enclosing
 * transaction's rollback. With no transactions manager, or one that is not
 * Laravel's, none is open to wait on.
 *
 * The manager is resolved from the application current on every call, never
 * kept, so the manager the testing transaction traits swap in is the one
 * consulted. Stateless (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class OpenTransactions
{
    /** @var string The container key Laravel binds its transactions manager under. */
    private const string MANAGER = 'db.transactions';

    /**
     * Laravel's transactions manager, as the application current holds it, or
     * `null` for none, or one that is not Laravel's, which no transaction's end
     * can be waited on through.
     *
     * @return ?\Illuminate\Database\DatabaseTransactionsManager
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public static function manager(): ?DatabaseTransactionsManager
    {
        $container = Container::getInstance();
        $manager   = $container->bound(self::MANAGER) ? $container->make(self::MANAGER) : null;

        return $manager instanceof DatabaseTransactionsManager ? $manager : null;
    }

    /**
     * The transactions the manager lets callbacks apply to that are still open
     * on the connection, outermost first.
     *
     * @param  \Illuminate\Database\DatabaseTransactionsManager  $manager
     * @param  \Illuminate\Database\Connection  $connection
     * @return array<int, \Illuminate\Database\DatabaseTransactionRecord>
     */
    public static function on(DatabaseTransactionsManager $manager, Connection $connection): array
    {
        $name  = $connection->getName();
        $level = $connection->transactionLevel();

        return $manager->callbackApplicableTransactions()
            ->filter(static fn (DatabaseTransactionRecord $transaction): bool => $transaction->connection === $name && $transaction->level <= $level)
            ->all();
    }
}
