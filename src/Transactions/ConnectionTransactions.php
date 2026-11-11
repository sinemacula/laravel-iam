<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Transactions;

use Illuminate\Container\Container;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\DatabaseTransactionRecord;

/**
 * The transactions open on one connection, since Laravel's `afterCommit()`
 * waits on whichever connection opened last.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ConnectionTransactions
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Run the work once the connection's transactions commit, at once when none
     * is open, and never on rollback.
     *
     * @param  ?string  $connection
     * @param  \Closure(): mixed  $work
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public static function afterCommit(?string $connection, \Closure $work): void
    {
        $open = self::open($connection);

        if ($open === []) {

            $work();

            return;
        }

        end($open)->addCallback($work);
    }

    /**
     * The transactions open on the connection that callbacks can wait on,
     * outermost first, or none without a manager.
     *
     * The manager is read on each call, since the testing traits swap their own
     * in, and still lists a transaction while its rollback callbacks run.
     *
     * @param  ?string  $connection
     * @return list<\Illuminate\Database\DatabaseTransactionRecord>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public static function open(?string $connection): array
    {
        $container = Container::getInstance();

        if (!$container->bound('db.transactions')) {
            return [];
        }

        $manager  = $container->make('db.transactions');
        $database = $container->make(DatabaseManager::class)->connection($connection);
        $name     = $database->getName();
        $level    = $database->transactionLevel();

        return array_values($manager->callbackApplicableTransactions()
            ->filter(static fn (DatabaseTransactionRecord $transaction): bool => $transaction->connection === $name && $transaction->level <= $level)
            ->all());
    }
}
