<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Transactions;

use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\DeadlockException;
use SineMacula\Laravel\Iam\Storage\StorageConnection;

/**
 * Runs a change that spans members in one transaction on the storage
 * connection, retrying the whole of it after a concurrency failure (IAM-11.1,
 * IAM-11.2).
 *
 * It retries only when it opened the outermost transaction: nothing can be
 * retried from inside a savepoint, so inside a transaction the caller opened,
 * the work runs in that transaction and every failure is rethrown for the
 * transaction's owner to retry, in a form that owner's retry recognises. The
 * work runs there in a savepoint that is rolled back whenever it fails, so a
 * caller that catches the failure and commits keeps none of the work's writes.
 *
 * Each attempt it opens is begun, committed and rolled back through the
 * connection's own transaction methods, so a failure at commit, which leaves
 * some drivers (SQLite among them) still inside the transaction, is rolled back
 * with the after-commit callbacks the attempt queued, on every supported
 * Laravel version, before the work is run again or the failure is rethrown. A
 * failure once the attempt has committed, from an after-commit callback or a
 * `committed` listener, is rethrown and never retried, as Laravel's own
 * transactions leave it, since running the work again would apply its change
 * twice.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final readonly class CrossMemberTransaction
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Database\DatabaseManager  $database
     * @param  \SineMacula\Laravel\Iam\Storage\StorageConnection  $storage
     * @param  \SineMacula\Laravel\Iam\Transactions\RetrySettings  $settings
     * @param  \SineMacula\Laravel\Iam\Transactions\ConcurrencyFailures  $failures
     */
    public function __construct(

        /** The connections the transaction runs on. */
        private DatabaseManager $database,

        /** The storage connection's name. */
        private StorageConnection $storage,

        /** How many times the work is attempted. */
        private RetrySettings $settings,

        /** Which failures the work is retried after. */
        private ConcurrencyFailures $failures,
    ) {}

    /**
     * Run the work in one transaction on the storage connection and return what
     * it returns. When no transaction is open there, the work is retried as a
     * whole after a concurrency failure, up to the given attempts or the
     * configured ones; inside an open transaction it runs once and every
     * failure is rethrown.
     *
     * @template T
     *
     * @param  \Closure(): T  $work
     * @param  ?int  $attempts
     * @return T
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function run(\Closure $work, ?int $attempts = null): mixed
    {
        if ($attempts !== null && $attempts < 1) {
            throw new \InvalidArgumentException(sprintf('A cross-member transaction is attempted at least once, the first included: [%d] attempts given.', $attempts));
        }

        $connection = $this->database->connection($this->storage->name());

        if ($connection->transactionLevel() > 0) {
            return $this->runInside($connection, $work);
        }

        $attempts ??= $this->settings->attempts();

        for ($attempt = 1;; $attempt++) {

            $connection->beginTransaction();

            try {
                $result = $work();

                $connection->commit();

                return $result;
            } catch (\Throwable $exception) {

                if (!$this->isRetriedAfter($exception, $connection, $attempt < $attempts)) {
                    throw $exception;
                }
            }
        }
    }

    /**
     * Run the work once, in a savepoint inside the caller's transaction, and
     * rethrow its failure as the caller's transaction should see it, with
     * everything the work wrote rolled back.
     *
     * Laravel's nested transaction rolls back to its savepoint after any other
     * failure, but after a concurrency failure it throws its
     * `DeadlockException`, which it throws exactly when its detector sees one,
     * having only lowered the transaction level before 13.40. Where the
     * database rolled back the failed statement alone (a lock wait timeout on
     * MySQL, `database is locked` on SQLite, a changed record on MariaDB), the
     * work's earlier writes would stay in the caller's transaction, so the work
     * is rolled back to its savepoint here, on every supported version.
     *
     * @template T
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \Closure(): T  $work
     * @return T
     *
     * @throws \Throwable
     */
    private function runInside(Connection $connection, \Closure $work): mixed
    {
        $level = $connection->transactionLevel();

        try {
            return $connection->transaction($work);
        } catch (\Throwable $exception) {

            if ($exception instanceof DeadlockException) {
                self::rollBackToSavepoint($connection, $level);
            }

            throw $this->failures->forCaller($exception);
        }
    }

    /**
     * Roll back to the savepoint the work's nested transaction opened above the
     * caller's level, named as Laravel names it, where the connection's grammar
     * has savepoints, as Laravel 13.40 does itself. A rollback that fails is
     * left as it is: the database has discarded the savepoint already, as MySQL
     * does with the whole transaction after a deadlock, or the connection is
     * lost, and the work's own failure is the one to throw on.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  int  $level
     * @return void
     */
    private static function rollBackToSavepoint(Connection $connection, int $level): void
    {
        $grammar = $connection->getQueryGrammar();

        if (!$grammar->supportsSavepoints()) {
            return;
        }

        try {
            $connection->getPdo()->exec($grammar->compileSavepointRollBack('trans' . ($level + 1)));
        } catch (\Throwable) {
            // The savepoint is gone already, with whatever the work wrote.
        }
    }

    /**
     * Tell whether the work is run again after the attempt's failure: only when
     * the attempt has not committed, is rolled back, is not the last one, and
     * failed on a concurrency failure. The attempt is rolled back first
     * whenever it has not committed, the last one included.
     *
     * @param  \Throwable  $exception
     * @param  \Illuminate\Database\Connection  $connection
     * @param  bool  $attemptsLeft
     * @return bool
     */
    private function isRetriedAfter(\Throwable $exception, Connection $connection, bool $attemptsLeft): bool
    {
        return !self::isCommitted($connection) && self::rolledBack($connection) && $attemptsLeft && $this->failures->isRetryable($exception);
    }

    /**
     * Tell whether the attempt has committed although it failed: Laravel lowers
     * the transaction level only once the database has committed, and then runs
     * the after-commit callbacks and the `committed` listeners, so a failure
     * met with no transaction left open is one of theirs. The attempt's change
     * is kept, and the work is not run again, since that would apply it twice.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return bool
     */
    private static function isCommitted(Connection $connection): bool
    {
        return $connection->transactionLevel() === 0;
    }

    /**
     * Roll the connection back to no transaction at all, whatever the work left
     * open, discarding the after-commit callbacks the attempt queued, and tell
     * whether it was. A rollback that fails, as on a lost connection, leaves
     * the work's own failure as the one rethrown, and the work is not run again
     * in what is left of the transaction.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return bool
     */
    private static function rolledBack(Connection $connection): bool
    {
        try {
            $connection->rollBack(0);
        } catch (\Throwable) {
            return false;
        }

        return true;
    }
}
