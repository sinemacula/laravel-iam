<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Transactions;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Database\ConcurrencyErrorDetector;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\DeadlockException;
use SineMacula\Laravel\Iam\Storage\StorageConnection;
use SineMacula\Laravel\Sso\Exceptions\LinkCandidatesChanged;

/**
 * Runs a change that spans members in one transaction on the storage
 * connection, retried on a concurrency failure only when outermost.
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
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \Illuminate\Contracts\Database\ConcurrencyErrorDetector  $detector
     */
    public function __construct(

        /** Resolves the storage connection. */
        private DatabaseManager $database,

        /** Names the storage connection. */
        private StorageConnection $storage,

        /** Holds `iam.transactions.attempts`. */
        private Repository $config,

        /** Laravel's concurrency detector, as the application binds it. */
        private ConcurrencyErrorDetector $detector,
    ) {}

    /**
     * Run the work, retried up to the given or configured attempts.
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
        $attempts ??= $this->config->get('iam.transactions.attempts', 3);

        if (!is_int($attempts) || $attempts < 1) {
            throw new \InvalidArgumentException('A cross-member transaction must be attempted at least once.');
        }

        $connection = $this->database->connection($this->storage->name());

        return $connection->transaction(fn (): mixed => $this->recognisably($work), $attempts);
    }

    /**
     * Run the work, rethrowing any concurrency failure as SQLSTATE 40001.
     *
     * Laravel's detector misses SSO's `LinkCandidatesChanged`, and a nested
     * transaction drops PostgreSQL's string SQLSTATE.
     *
     * @template T
     *
     * @param  \Closure(): T  $work
     * @return T
     *
     * @throws \Illuminate\Database\DeadlockException
     * @throws \Throwable
     */
    private function recognisably(\Closure $work): mixed
    {
        try {
            return $work();
        } catch (\Throwable $exception) {

            for ($link = $exception; $link !== null; $link = $link->getPrevious()) {

                if ($link instanceof LinkCandidatesChanged || $this->detector->causedByConcurrencyError($link)) {
                    throw new DeadlockException($exception->getMessage(), 40001, $exception);
                }
            }

            throw $exception;
        }
    }
}
