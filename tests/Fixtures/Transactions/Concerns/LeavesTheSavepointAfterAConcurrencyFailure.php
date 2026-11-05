<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Transactions\Concerns;

use Illuminate\Database\DeadlockException;

/**
 * Handles a failure inside a nested transaction as Laravel 12.40 to 12.x and
 * 13.3 to 13.39 handle it: a concurrency failure lowers the transaction level
 * and is thrown on in a `DeadlockException`, without rolling back to the
 * savepoint the nested transaction opened. Laravel 13.40 is the first version
 * that rolls back to it; this lets the tests run the older behaviour on any
 * supported version.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \Illuminate\Database\Connection
 */
trait LeavesTheSavepointAfterAConcurrencyFailure
{
    /**
     * Handle a failure inside a transaction, leaving a nested transaction's
     * savepoint in place after a concurrency failure.
     *
     * @param  \Throwable  $e
     * @param  mixed  $currentAttempt
     * @param  mixed  $maxAttempts
     * @return void
     *
     * @throws \Illuminate\Database\DeadlockException
     */
    #[\Override]
    protected function handleTransactionException(\Throwable $e, mixed $currentAttempt, mixed $maxAttempts): void
    {
        if ($this->causedByConcurrencyError($e) && $this->transactions > 1) {
            $this->transactions--;

            $this->transactionsManager?->rollback($this->getName(), $this->transactions);

            throw new DeadlockException($e->getMessage(), is_int($e->getCode()) ? $e->getCode() : 0, $e);
        }

        parent::handleTransactionException($e, $currentAttempt, $maxAttempts);
    }
}
