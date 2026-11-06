<?php

declare(strict_types = 1);

namespace Tests\Unit\Transactions;

use Illuminate\Contracts\Database\ConcurrencyErrorDetector as ConcurrencyErrorDetectorContract;
use Illuminate\Database\ConcurrencyErrorDetector;
use Illuminate\Database\DeadlockException;
use Illuminate\Database\QueryException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Transactions\ConcurrencyFailures;
use SineMacula\Laravel\Sso\Exceptions\LinkCandidatesChanged;

/**
 * Unit tests for telling a failure the whole cross-member transaction may be
 * retried after from one it may not, as MySQL and PostgreSQL raise them and as
 * Laravel wraps them inside a nested transaction.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConcurrencyFailures::class)]
final class ConcurrencyFailuresTest extends TestCase
{
    /** @var string The message MySQL fails a deadlock victim with. */
    private const string MYSQL_DEADLOCK = 'SQLSTATE[40001]: Serialization failure: 1213 Deadlock found when trying to get lock; try restarting transaction';

    /** @var string The message MySQL fails a lock wait that timed out with. */
    private const string MYSQL_LOCK_WAIT_TIMEOUT = 'SQLSTATE[HY000]: General error: 1205 Lock wait timeout exceeded; try restarting transaction';

    /** @var string The message PostgreSQL fails a transaction that cannot be serialised with. */
    private const string PGSQL_SERIALIZATION_FAILURE = 'SQLSTATE[40001]: Serialization failure: 7 ERROR:  could not serialize access due to concurrent update';

    /** @var string The message PostgreSQL fails a deadlock victim with. */
    private const string PGSQL_DEADLOCK = 'SQLSTATE[40P01]: Deadlock detected: 7 ERROR:  deadlock detected';

    /** @var string The message a unique key violation fails with. */
    private const string UNIQUE_VIOLATION = 'SQLSTATE[23000]: Integrity constraint violation: 1062 Duplicate entry \'1\' for key \'PRIMARY\'';

    /**
     * Rows of `[failure]` the whole transaction may be retried after: the
     * servers' concurrency failures as the query that met them throws them, as
     * Laravel's `DeadlockException` wraps them inside a nested transaction (a
     * string SQLSTATE lost as code `0`), further down a chain, and SSO's
     * `LinkCandidatesChanged`.
     *
     * @return iterable<string, array{0: \Throwable}>
     */
    public static function provideRetryableFailures(): iterable
    {
        yield 'mysql deadlock' => [self::queryFailure('40001', self::MYSQL_DEADLOCK)];

        yield 'mysql lock wait timeout' => [self::queryFailure('HY000', self::MYSQL_LOCK_WAIT_TIMEOUT)];

        yield 'pgsql serialisation failure' => [self::queryFailure('40001', self::PGSQL_SERIALIZATION_FAILURE)];

        yield 'pgsql deadlock' => [self::queryFailure('40P01', self::PGSQL_DEADLOCK)];

        yield 'mysql deadlock in a nested transaction' => [self::nested(self::queryFailure('40001', self::MYSQL_DEADLOCK))];

        yield 'pgsql serialisation failure in a nested transaction' => [self::nested(self::queryFailure('40001', self::PGSQL_SERIALIZATION_FAILURE))];

        yield 'pgsql deadlock in a nested transaction' => [self::nested(self::queryFailure('40P01', self::PGSQL_DEADLOCK))];

        $serialization = self::nested(self::queryFailure('40001', self::PGSQL_SERIALIZATION_FAILURE));

        yield 'serialisation failure further down the chain' => [new \RuntimeException('Linking failed.', 0, new \LogicException('Writing failed.', 0, $serialization))];

        yield 'link candidates changed' => [LinkCandidatesChanged::retryWhole()];

        yield 'link candidates changed further down the chain' => [new \RuntimeException('Linking failed.', 0, LinkCandidatesChanged::retryWhole())];
    }

    /**
     * A concurrency failure, wherever it sits in the chain, makes the
     * transaction retryable.
     *
     * @param  \Throwable  $failure
     * @return void
     */
    #[DataProvider('provideRetryableFailures')]
    public function testAConcurrencyFailureAnywhereInTheChainIsRetryable(\Throwable $failure): void
    {
        self::assertTrue(self::failures()->isRetryable($failure));
    }

    /**
     * Rows of `[failure]` the whole transaction may not be retried after:
     * nothing in their chain is a concurrency failure.
     *
     * @return iterable<string, array{0: \Throwable}>
     */
    public static function provideFinalFailures(): iterable
    {
        yield 'unique violation' => [self::queryFailure('23000', self::UNIQUE_VIOLATION)];

        yield 'unique violation in a nested transaction' => [new \RuntimeException('Writing failed.', 0, self::queryFailure('23000', self::UNIQUE_VIOLATION))];

        yield 'plain failure' => [new \RuntimeException('Something went wrong.')];

        yield 'serialisation failure code on an exception that is not a database one' => [new \RuntimeException('Something went wrong.', 40001)];
    }

    /**
     * A failure with no concurrency failure in its chain is not retryable.
     *
     * @param  \Throwable  $failure
     * @return void
     */
    #[DataProvider('provideFinalFailures')]
    public function testAFailureWithNoConcurrencyFailureInTheChainIsNotRetryable(\Throwable $failure): void
    {
        self::assertFalse(self::failures()->isRetryable($failure));
    }

    /**
     * The detector the application binds decides what a concurrency failure is,
     * for every link in the chain.
     *
     * @return void
     */
    public function testTheBoundDetectorDecidesWhatAConcurrencyFailureIs(): void
    {
        $detector = new class implements ConcurrencyErrorDetectorContract {
            /**
             * Treat only a failure saying so as a concurrency failure.
             *
             * @param  \Throwable  $e
             * @return bool
             */
            #[\Override]
            public function causedByConcurrencyError(\Throwable $e): bool
            {
                return $e->getMessage() === 'Busy.';
            }
        };

        $failures = new ConcurrencyFailures($detector);

        self::assertTrue($failures->isRetryable(new \RuntimeException('Writing failed.', 0, new \RuntimeException('Busy.'))));
        self::assertFalse($failures->isRetryable(self::queryFailure('40001', self::MYSQL_DEADLOCK)));
    }

    /**
     * A `DeadlockException` Laravel's detector cannot recognise, as around
     * PostgreSQL's serialisation failure, gives way to the first exception in
     * its chain the detector recognises, so the caller's retry sees it.
     *
     * @return void
     */
    public function testAWrappedFailureTheDetectorCannotRecogniseIsUnwrappedForTheCaller(): void
    {
        $serialization = self::queryFailure('40001', self::PGSQL_SERIALIZATION_FAILURE);
        $deeper        = new DeadlockException('Linking failed.', 0, new \RuntimeException('Writing failed.', 0, $serialization));

        self::assertSame($serialization, self::failures()->forCaller(self::nested($serialization)));
        self::assertSame($serialization, self::failures()->forCaller($deeper));
    }

    /**
     * Rows of `[failure]` the caller sees as they are: a wrapper the detector
     * recognises, a wrapper around nothing it recognises, and failures that are
     * not wrappers, recognisable or not.
     *
     * @return iterable<string, array{0: \Throwable}>
     */
    public static function provideFailuresForTheCallerAsTheyAre(): iterable
    {
        yield 'mysql deadlock in a nested transaction' => [self::nested(self::queryFailure('40001', self::MYSQL_DEADLOCK))];

        yield 'pgsql deadlock in a nested transaction' => [self::nested(self::queryFailure('40P01', self::PGSQL_DEADLOCK))];

        yield 'wrapper around nothing recognisable' => [new DeadlockException('Writing failed.', 0, new \RuntimeException('Something went wrong.'))];

        yield 'wrapper around nothing' => [new DeadlockException('Writing failed.')];

        yield 'pgsql serialisation failure' => [self::queryFailure('40001', self::PGSQL_SERIALIZATION_FAILURE)];

        yield 'plain failure around a serialisation failure' => [new \RuntimeException('Linking failed.', 0, self::queryFailure('40001', self::PGSQL_SERIALIZATION_FAILURE))];

        yield 'link candidates changed' => [LinkCandidatesChanged::retryWhole()];
    }

    /**
     * Any other failure is handed to the caller as it is.
     *
     * @param  \Throwable  $failure
     * @return void
     */
    #[DataProvider('provideFailuresForTheCallerAsTheyAre')]
    public function testAnyOtherFailureIsHandedToTheCallerAsItIs(\Throwable $failure): void
    {
        self::assertSame($failure, self::failures()->forCaller($failure));
    }

    /**
     * Rows of `[failure, raised]`: a concurrency failure the database raised,
     * as Laravel's `DeadlockException` wraps it in a nested transaction, once
     * or once at each level of nesting, or further down a chain, whether or not
     * the detector recognises the wrapper itself, and the failure as the
     * database raised it.
     *
     * @return iterable<string, array{0: \Throwable, 1: \Throwable}>
     */
    public static function provideWrappedFailuresAsRaised(): iterable
    {
        $mysqlDeadlock       = self::queryFailure('40001', self::MYSQL_DEADLOCK);
        $mysqlLockWait       = self::queryFailure('HY000', self::MYSQL_LOCK_WAIT_TIMEOUT);
        $pgsqlSerialisation  = self::queryFailure('40001', self::PGSQL_SERIALIZATION_FAILURE);
        $pgsqlDeadlock       = self::queryFailure('40P01', self::PGSQL_DEADLOCK);
        $deeperSerialisation = self::queryFailure('40001', self::PGSQL_SERIALIZATION_FAILURE);
        $deeper              = new DeadlockException('Linking failed.', 0, new \RuntimeException('Writing failed.', 0, $deeperSerialisation));
        $twiceNested         = self::queryFailure('40001', self::MYSQL_DEADLOCK);

        yield 'mysql deadlock in a nested transaction' => [self::nested($mysqlDeadlock), $mysqlDeadlock];

        yield 'mysql lock wait timeout in a nested transaction' => [self::nested($mysqlLockWait), $mysqlLockWait];

        yield 'pgsql serialisation failure in a nested transaction' => [self::nested($pgsqlSerialisation), $pgsqlSerialisation];

        yield 'pgsql deadlock in a nested transaction' => [self::nested($pgsqlDeadlock), $pgsqlDeadlock];

        yield 'mysql deadlock two nested transactions deep' => [self::nested(self::nested($twiceNested)), $twiceNested];

        yield 'serialisation failure further down the chain' => [$deeper, $deeperSerialisation];
    }

    /**
     * For a caller with no transaction open, Laravel's `DeadlockException`
     * gives way to the failure the database raised, the first in its chain that
     * is no such wrapper and that the detector recognises, even where the
     * detector recognises the wrapper too.
     *
     * @param  \Throwable  $failure
     * @param  \Throwable  $raised
     * @return void
     */
    #[DataProvider('provideWrappedFailuresAsRaised')]
    public function testAWrappedFailureIsHandedOnAsTheDatabaseRaisedIt(\Throwable $failure, \Throwable $raised): void
    {
        self::assertSame($raised, self::failures()->asRaised($failure));
    }

    /**
     * Rows of `[failure]` handed on as they are to a caller with no transaction
     * open: wrappers around nothing the detector recognises but another
     * wrapper, or around nothing at all, and failures that are not wrappers,
     * recognisable or not.
     *
     * @return iterable<string, array{0: \Throwable}>
     */
    public static function provideFailuresAsRaised(): iterable
    {
        yield 'wrapper around nothing recognisable' => [new DeadlockException('Writing failed.', 0, new \RuntimeException('Something went wrong.'))];

        yield 'wrapper around nothing but a wrapper' => [new DeadlockException('Writing failed.', 0, new DeadlockException(self::MYSQL_DEADLOCK))];

        yield 'wrapper around nothing' => [new DeadlockException('Writing failed.')];

        yield 'mysql deadlock' => [self::queryFailure('40001', self::MYSQL_DEADLOCK)];

        yield 'plain failure around a serialisation failure' => [new \RuntimeException('Linking failed.', 0, self::queryFailure('40001', self::PGSQL_SERIALIZATION_FAILURE))];

        yield 'unique violation' => [self::queryFailure('23000', self::UNIQUE_VIOLATION)];

        yield 'link candidates changed' => [LinkCandidatesChanged::retryWhole()];
    }

    /**
     * Any other failure is handed to a caller with no transaction open as it
     * is.
     *
     * @param  \Throwable  $failure
     * @return void
     */
    #[DataProvider('provideFailuresAsRaised')]
    public function testAnyOtherFailureIsHandedOnAsRaisedAsItIs(\Throwable $failure): void
    {
        self::assertSame($failure, self::failures()->asRaised($failure));
    }

    /**
     * Build the failures with Laravel's own detector.
     *
     * @return \SineMacula\Laravel\Iam\Transactions\ConcurrencyFailures
     */
    private static function failures(): ConcurrencyFailures
    {
        return new ConcurrencyFailures(new ConcurrencyErrorDetector);
    }

    /**
     * Build the failure a query meets as PDO raises it, with the server's
     * SQLSTATE as a string code, and as Laravel throws it on.
     *
     * @param  string  $sqlState
     * @param  string  $message
     * @return \Illuminate\Database\QueryException
     */
    private static function queryFailure(string $sqlState, string $message): QueryException
    {
        $failure = new \PDOException($message);

        (new \ReflectionProperty(\Exception::class, 'code'))->setValue($failure, $sqlState);

        $failure->errorInfo = [$sqlState, 1, $message];

        return new QueryException('testing', 'update `rows` set `value` = ?', [1], $failure);
    }

    /**
     * Wrap the failure as Laravel does when it is met inside a nested
     * transaction: in a `DeadlockException` whose code is `0` unless the
     * failure's own is an integer.
     *
     * @param  \Throwable  $failure
     * @return \Illuminate\Database\DeadlockException
     */
    private static function nested(\Throwable $failure): DeadlockException
    {
        return new DeadlockException($failure->getMessage(), is_int($failure->getCode()) ? $failure->getCode() : 0, $failure);
    }
}
