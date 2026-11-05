<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Transactions;

use Illuminate\Contracts\Database\ConcurrencyErrorDetector;
use Illuminate\Database\DeadlockException;
use SineMacula\Laravel\Sso\Exceptions\LinkCandidatesChanged;

/**
 * Tells whether a failed cross-member transaction may be retried as a whole.
 *
 * It walks the exception and every previous exception, since Laravel wraps a
 * failure inside a nested transaction in a `DeadlockException` whose own code
 * is lost, and retries when any of them is a concurrency failure as Laravel's
 * detector sees one (SQLSTATE 40001, a deadlock, a lock wait timeout) or SSO's
 * `LinkCandidatesChanged`.
 *
 * It also hands a failure met inside a caller's transaction on in a form the
 * caller's own retry recognises: Laravel's wrapper keeps the message but not
 * the SQLSTATE, and PostgreSQL's serialisation failure says nothing Laravel's
 * detector matches without it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ConcurrencyFailures
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Database\ConcurrencyErrorDetector  $detector
     */
    public function __construct(

        /** Laravel's concurrency detector, as the application binds it. */
        private ConcurrencyErrorDetector $detector,
    ) {}

    /**
     * Whether the exception, or any exception before it, is a failure the whole
     * transaction may be retried after.
     *
     * @param  \Throwable  $exception
     * @return bool
     */
    public function isRetryable(\Throwable $exception): bool
    {
        for ($link = $exception; $link !== null; $link = $link->getPrevious()) {

            if ($link instanceof LinkCandidatesChanged || $this->detector->causedByConcurrencyError($link)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Return the failure as the caller's transaction should see it: Laravel's
     * `DeadlockException` that its detector cannot recognise, as when it wraps
     * PostgreSQL's serialisation failure, gives way to the first exception in
     * its chain the detector does recognise, so a caller's transaction that
     * retries on a concurrency failure retries; anything else is returned as it
     * is.
     *
     * @param  \Throwable  $exception
     * @return \Throwable
     */
    public function forCaller(\Throwable $exception): \Throwable
    {
        if (!$exception instanceof DeadlockException || $this->detector->causedByConcurrencyError($exception)) {
            return $exception;
        }

        for ($link = $exception->getPrevious(); $link !== null; $link = $link->getPrevious()) {

            if ($this->detector->causedByConcurrencyError($link)) {
                return $link;
            }
        }

        return $exception;
    }
}
