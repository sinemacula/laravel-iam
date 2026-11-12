<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Transactions;

use Illuminate\Container\Container;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\DatabaseTransactionRecord;

/**
 * The transactions open on one connection, since Laravel's manager lists every
 * connection's together.
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
     * The connection's open transactions, outermost first. The manager is read
     * on each call, since the testing traits swap their own in, and still lists
     * a transaction while its rollback callbacks run.
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
