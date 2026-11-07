<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Transactions;

use Illuminate\Container\Container;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseTransactionRecord;
use Illuminate\Database\DatabaseTransactionsManager;
use Illuminate\Database\Events\TransactionCommitted;

/**
 * Defers work until the transactions open on one connection have committed and
 * every callback queued on them has run.
 *
 * Laravel's own `afterCommit()` queues a callback on the transaction opened
 * last on whichever connection, so a transaction open on another connection
 * when the work is queued would run it when that one commits, and drop it when
 * that one rolls back. This holds the work for the innermost transaction open
 * on the connection given: it runs once the outermost transaction there
 * commits, never when that rolls back (a savepoint rolled back drops it with
 * the savepoint's writes), and the work runs at once when the connection has no
 * transaction open.
 *
 * The work is held (`CommittedWork`) as it is queued, and dropped by a rollback
 * callback of the transaction it was queued in, so nothing queued on the commit
 * before it can keep it from being held. It is released by Laravel's
 * `TransactionCommitted` event (`committed()`), which the connection fires once
 * every callback queued on the transaction has run, and only for a commit that
 * leaves no transaction open on the connection, so a savepoint's commit inside
 * a later transaction never releases work an earlier one left. Work that begins
 * a transaction, run from a commit callback, would begin an outermost
 * transaction before the callbacks queued after its own had run, and
 * `laravel-sso` drops each event of its own whose callback finds one begun (its
 * `TransactionGenerations`), the report of the very change that queued the work
 * among them. What the work throws propagates from the commit, the change
 * already durable and every callback run.
 *
 * A commit callback that fails stops Laravel running the rest, and the
 * connection then fires no `TransactionCommitted`: the work stays held, the
 * change it waited for durable. The end of the unit of work releases it
 * (`settle()`): the request's or the console command's termination, a queued
 * job's end, and `Iam::resetWorkerState()`, each releasing the work held for
 * every connection with no transaction open, and reporting what it throws, the
 * caller's own work being over. A connection with no events dispatcher fires no
 * event, so there a commit callback releases the work instead.
 *
 * The transactions manager and the held work's record are resolved from the
 * application current when each step runs, never from a container kept since,
 * so the manager the testing transaction traits swap in is the one consulted,
 * and the record is that of the request or the job whose transaction commits,
 * an Octane request's own sandbox included. Stateless (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AfterConnectionCommits
{
    /** @var string The container key Laravel binds its transactions manager under. */
    private const string MANAGER = 'db.transactions';

    /**
     * Run the work once the transactions open on the connection have committed
     * and every callback queued on them has run, or at once when none is open.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \Closure(): void  $work
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function run(Connection $connection, \Closure $work): void
    {
        $pending = self::innermost($connection);

        if ($pending === null) {

            $work();

            return;
        }

        $held   = self::held();
        $ticket = $held->hold($connection, $work);

        $pending->addCallbackForRollback(static function () use ($held, $connection, $ticket): void {

            $held->drop($connection, $ticket);
        });

        if ($connection->getEventDispatcher() !== null) {
            return;
        }

        $pending->addCallback(static fn () => self::release($held, $connection));
    }

    /**
     * Release the work held for the connection that committed, once the commit
     * leaves no transaction open there.
     *
     * @param  \Illuminate\Database\Events\TransactionCommitted  $event
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    public function committed(TransactionCommitted $event): void
    {
        self::release(self::held(), $event->connection);
    }

    /**
     * Release, as the unit of work ends, the work still held for every
     * connection with no transaction open, and report what it throws.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function settle(): void
    {
        $held = self::held();

        foreach ($held->connections() as $connection) {

            try {
                self::release($held, $connection);
            } catch (\Throwable $exception) {
                Container::getInstance()->make(ExceptionHandler::class)->report($exception);
            }
        }
    }

    /**
     * Release the work held for the connection, unless a transaction is still
     * open there.
     *
     * @param  \SineMacula\Laravel\Iam\Transactions\CommittedWork  $held
     * @param  \Illuminate\Database\Connection  $connection
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    private static function release(CommittedWork $held, Connection $connection): void
    {
        if (self::innermost($connection) !== null) {
            return;
        }

        $held->release($connection);
    }

    /**
     * The record of the work held for the current request or job.
     *
     * @return \SineMacula\Laravel\Iam\Transactions\CommittedWork
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private static function held(): CommittedWork
    {
        return Container::getInstance()->make(CommittedWork::class);
    }

    /**
     * The innermost transaction open on the connection that commit callbacks
     * apply to, or `null` for none, or without a transactions manager.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return ?\Illuminate\Database\DatabaseTransactionRecord
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private static function innermost(Connection $connection): ?DatabaseTransactionRecord
    {
        $container = Container::getInstance();
        $manager   = $container->bound(self::MANAGER) ? $container->make(self::MANAGER) : null;

        if (!$manager instanceof DatabaseTransactionsManager) {
            return null;
        }

        $name = $connection->getName();

        /** @var ?\Illuminate\Database\DatabaseTransactionRecord */
        return $manager->callbackApplicableTransactions()
            ->filter(static fn (DatabaseTransactionRecord $transaction): bool => $transaction->connection === $name)
            ->last();
    }
}
