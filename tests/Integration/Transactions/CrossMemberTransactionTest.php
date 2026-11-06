<?php

declare(strict_types = 1);

namespace Tests\Integration\Transactions;

use Illuminate\Contracts\Database\ConcurrencyErrorDetector;
use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\DeadlockException;
use Illuminate\Database\Events\TransactionCommitted;
use Illuminate\Database\Events\TransactionCommitting;
use Illuminate\Database\Query\Grammars\Grammar;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Iam\Storage\StorageConnection;
use SineMacula\Laravel\Iam\Transactions\ConcurrencyFailures;
use SineMacula\Laravel\Iam\Transactions\CrossMemberTransaction;
use SineMacula\Laravel\Iam\Transactions\RetrySettings;
use SineMacula\Laravel\Sso\Exceptions\LinkCandidatesChanged;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Fixtures\Transactions\SavepointLeavingConnections;
use Tests\TestCase;

/**
 * Integration tests for running a change that spans members in one transaction
 * on the storage connection: the whole of it is retried after a concurrency
 * failure when the transaction is the outermost one, up to the configured
 * attempts, and run once with every failure rethrown inside a transaction the
 * caller opened, in a form the caller's own retry recognises, with the work's
 * savepoint rolled back on every supported Laravel version. A failed attempt is
 * rolled back with the after-commit callbacks it queued.
 *
 * The retry rules run on every connection. A real serialisation failure, on
 * PostgreSQL at REPEATABLE READ, and a real deadlock, on MySQL and PostgreSQL
 * at READ COMMITTED and REPEATABLE READ, each provoked through a second
 * connection of the test's own, are skipped on SQLite, which serialises every
 * transaction; a real lock wait timeout runs on MySQL alone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CrossMemberTransaction::class)]
final class CrossMemberTransactionTest extends TestCase
{
    use RunsAtIsolationLevels;

    /** @var string The table the work writes to. */
    private const string TABLE = 'iam_transaction_rows';

    /** @var int How many rows the other side writes first, so MySQL, which rolls back the lighter side of a deadlock, picks the work's side. */
    private const int WEIGHT_ROWS = 20;

    /** @var int How long either side waits for the other before giving up, in seconds. */
    private const int SIGNAL_TIMEOUT_SECONDS = 10;

    /** @var int How long to wait between looks at the other side's session, in microseconds: longer than the tenth of a second MySQL serves `information_schema.innodb_trx` from a cache that every look within it keeps stale. */
    private const int LOCK_WAIT_POLL_MICROSECONDS = 150000;

    /** @var string The deadlock timeout of the work's side on PostgreSQL, whose side that checks for a deadlock first is the one rolled back. */
    private const string WORK_DEADLOCK_TIMEOUT = '10ms';

    /** @var string The deadlock timeout of the other side on PostgreSQL, long enough that it never checks first. */
    private const string OTHER_DEADLOCK_TIMEOUT = '30s';

    /** @var string The message PostgreSQL fails a transaction that cannot be serialised with. */
    private const string PGSQL_SERIALIZATION_FAILURE = 'SQLSTATE[40001]: Serialization failure: 7 ERROR:  could not serialize access due to concurrent update';

    /** @var string The message MySQL fails a deadlock victim with. */
    private const string MYSQL_DEADLOCK = 'SQLSTATE[40001]: Serialization failure: 1213 Deadlock found when trying to get lock; try restarting transaction';

    /** @var string The message PostgreSQL fails a deadlock victim with. */
    private const string PGSQL_DEADLOCK = 'SQLSTATE[40P01]: Deadlock detected: 7 ERROR:  deadlock detected';

    /** @var int The error code MySQL fails a deadlock victim with. */
    private const int MYSQL_DEADLOCK_ERROR = 1213;

    /** @var string The file SQLite connection whose commit another reader's lock holds up. */
    private const string LOCKING = 'locking';

    /** @var int How long the locking connection waits for a lock before failing, in milliseconds. */
    private const int LOCKING_BUSY_TIMEOUT = 50;

    /** @var string The message MySQL fails a statement that waited too long for a row lock with. */
    private const string LOCK_WAIT_TIMEOUT = 'SQLSTATE[HY000]: General error: 1205 Lock wait timeout exceeded; try restarting transaction';

    /** @var int How long the work waits for the row the other side locks on MySQL, in seconds. */
    private const int LOCK_WAIT_TIMEOUT_SECONDS = 1;

    /** @var ?string The file the locking connection's database is kept in, removed after the test. */
    private ?string $lockingFile = null;

    /**
     * Create the table the work writes to.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Schema::dropIfExists(self::TABLE);
        Schema::create(self::TABLE, static function (Blueprint $table): void {

            $table->integer('id')->primary();
            $table->integer('value');
        });
    }

    /**
     * Drop the table the work writes to.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists(self::TABLE);

        parent::tearDown();

        if ($this->lockingFile === null || !is_file($this->lockingFile)) {
            return;
        }

        unlink($this->lockingFile);
    }

    /**
     * The work runs in one transaction on the storage connection, not on the
     * default one, and what it returns is returned.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheWorkRunsInOneTransactionOnTheStorageConnection(): void
    {
        self::useStorageConnection();

        $levels = $this->transaction()->run(static fn (): array => [DB::connection('storage')->transactionLevel(), DB::connection()->transactionLevel()]);

        self::assertSame([1, 0], $levels);
        self::assertSame(0, DB::connection('storage')->transactionLevel());
    }

    /**
     * Rows of `[failure]` the whole work is retried after: a deadlock as the
     * query that met it throws it, a serialisation failure as Laravel throws it
     * on from a nested transaction, and SSO's `LinkCandidatesChanged`.
     *
     * @return iterable<string, array{0: \Throwable}>
     */
    public static function provideRetryableFailures(): iterable
    {
        yield 'deadlock' => [self::queryFailure('40001', 'SQLSTATE[40001]: Serialization failure: 1213 Deadlock found when trying to get lock; try restarting transaction')];

        $serialization = self::queryFailure('40001', self::PGSQL_SERIALIZATION_FAILURE);

        yield 'serialisation failure from a nested transaction' => [new DeadlockException($serialization->getMessage(), 0, $serialization)];

        yield 'link candidates changed' => [LinkCandidatesChanged::retryWhole()];
    }

    /**
     * After a concurrency failure the whole work is run again in a new
     * transaction, up to the configured attempts, and what the last attempt
     * returns is returned with only its writes kept.
     *
     * @param  \Throwable  $failure
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideRetryableFailures')]
    public function testTheWholeWorkIsRetriedAfterAConcurrencyFailureUntilItSucceeds(\Throwable $failure): void
    {
        Config::set('iam.transactions.attempts', 3);

        $attempts = 0;

        $result = $this->transaction()->run(static function () use (&$attempts, $failure): string {

            $attempts++;

            DB::table(self::TABLE)->insert(['id' => $attempts, 'value' => $attempts]);

            if ($attempts < 3) {
                throw $failure;
            }

            return 'attempt ' . $attempts;
        });

        self::assertSame('attempt 3', $result);
        self::assertSame(3, $attempts);
        self::assertSame([3], DB::table(self::TABLE)->pluck('id')->all());
    }

    /**
     * After the configured attempts, or the attempts the caller gives instead,
     * the last concurrency failure is rethrown and nothing the work wrote is
     * kept.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testItGivesUpAndRethrowsAfterTheLastAttempt(): void
    {
        Config::set('iam.transactions.attempts', 3);

        $failure = LinkCandidatesChanged::retryWhole();

        self::assertSame([3, $failure], $this->failingRun($failure));
        self::assertSame([2, $failure], $this->failingRun($failure, 2));
        self::assertSame([1, $failure], $this->failingRun($failure, 1));
        self::assertSame(0, DB::table(self::TABLE)->count());
    }

    /**
     * Rows of `[failure]`: each concurrency failure a member's nested
     * transaction meets, as the query that met it throws it.
     *
     * @return iterable<string, array{0: \Illuminate\Database\QueryException}>
     */
    public static function provideQueryConcurrencyFailures(): iterable
    {
        yield 'pgsql serialisation failure' => [self::queryFailure('40001', self::PGSQL_SERIALIZATION_FAILURE)];

        yield 'pgsql deadlock' => [self::queryFailure('40P01', self::PGSQL_DEADLOCK)];

        yield 'mysql deadlock' => [self::queryFailure('40001', self::MYSQL_DEADLOCK)];

        yield 'mysql lock wait timeout' => [self::queryFailure('HY000', self::LOCK_WAIT_TIMEOUT)];
    }

    /**
     * The last attempt's concurrency failure, met in a member's own nested
     * transaction, which Laravel wraps in its `DeadlockException`, reaches the
     * caller as the query threw it, with its SQLSTATE, so the caller and
     * Laravel's detector recognise it, and nothing the work wrote is kept.
     *
     * @param  \Illuminate\Database\QueryException  $failure
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideQueryConcurrencyFailures')]
    public function testTheLastAttemptsFailureInAMembersTransactionReachesTheCallerAsTheDatabaseRaisedIt(QueryException $failure): void
    {
        $runs   = 0;
        $thrown = null;

        try {
            $this->transaction()->run(static function () use (&$runs, $failure): void {

                $runs++;

                DB::transaction(static function () use ($runs, $failure): void {

                    DB::table(self::TABLE)->insert(['id' => $runs, 'value' => $runs]);

                    throw $failure;
                });
            }, 2);
        } catch (\Throwable $exception) {
            $thrown = $exception;
        }

        self::assertSame($failure, $thrown);
        self::assertSame(2, $runs);
        self::assertTrue($this->app?->make(ConcurrencyErrorDetector::class)->causedByConcurrencyError($thrown));
        self::assertSame(0, DB::transactionLevel());
        self::assertSame(0, DB::table(self::TABLE)->count());
    }

    /**
     * A failure that is not a concurrency failure is rethrown at once, without
     * running the work again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailureThatIsNotAConcurrencyFailureIsRethrownAtOnce(): void
    {
        $failure = new \RuntimeException('Something went wrong.');

        self::assertSame([1, $failure], $this->failingRun($failure, 3));
        self::assertSame(0, DB::table(self::TABLE)->count());
    }

    /**
     * Inside a transaction the caller opened on the storage connection, the
     * work runs once, in a savepoint, and its concurrency failure is rethrown
     * for the caller to retry its whole transaction; the caller's transaction
     * is still open, with what it wrote before.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testInsideACallersTransactionTheWorkRunsOnceAndItsFailureIsRethrown(): void
    {
        $failure = LinkCandidatesChanged::retryWhole();

        DB::beginTransaction();
        DB::table(self::TABLE)->insert(['id' => 100, 'value' => 100]);

        self::assertSame([1, $failure], $this->failingRun($failure, 3));
        self::assertSame(1, DB::transactionLevel());

        DB::commit();

        self::assertSame([100], DB::table(self::TABLE)->pluck('id')->all());
    }

    /**
     * Inside a caller's transaction, a failure Laravel itself sees as a
     * concurrency failure comes back as Laravel's `DeadlockException` around
     * it, after one run, with the caller's transaction level restored.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testInsideACallersTransactionADeadlockIsThrownOnAsLaravelWrapsIt(): void
    {
        $failure = new \RuntimeException('Deadlock found when trying to get lock; try restarting transaction');

        DB::beginTransaction();

        [$attempts, $thrown] = $this->failingRun($failure, 3);

        self::assertSame(1, $attempts);
        self::assertInstanceOf(DeadlockException::class, $thrown);
        self::assertSame($failure, $thrown->getPrevious());
        self::assertSame(1, DB::transactionLevel());

        DB::rollBack();
    }

    /**
     * Rows of `[leavesTheSavepoint]`: the connection as the installed Laravel
     * handles a concurrency failure in a nested transaction, and as Laravel
     * before 13.40 does, lowering the level without rolling back to the nested
     * transaction's savepoint.
     *
     * @return iterable<string, array{0: bool}>
     */
    public static function provideSavepointHandling(): iterable
    {
        yield 'as the installed Laravel handles it' => [false];

        yield 'as Laravel before 13.40 handles it' => [true];
    }

    /**
     * Inside a caller's transaction, a concurrency failure that the database
     * met on one statement alone, as a lock wait timeout on MySQL or `database
     * is locked` on SQLite, undoes everything the work wrote before it, on
     * every supported Laravel version: a caller that catches the failure and
     * commits keeps its own writes and none of the work's.
     *
     * @param  bool  $leavesTheSavepoint
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideSavepointHandling')]
    public function testInsideACallersTransactionTheWorksWritesAreUndoneAfterAConcurrencyFailure(bool $leavesTheSavepoint): void
    {
        $this->handleTheSavepoint($leavesTheSavepoint);

        DB::beginTransaction();
        DB::table(self::TABLE)->insert(['id' => 100, 'value' => 100]);

        $thrown = null;

        try {
            $this->transaction()->run(static function (): void {

                DB::table(self::TABLE)->insert(['id' => 200, 'value' => 200]);

                throw new \RuntimeException(self::LOCK_WAIT_TIMEOUT);
            });
        } catch (DeadlockException $thrown) {
            // Asserted below, beside what the caller's transaction kept.
        }

        self::assertInstanceOf(DeadlockException::class, $thrown);
        self::assertSame(1, DB::transactionLevel());

        DB::commit();

        self::assertSame([100], DB::table(self::TABLE)->pluck('id')->all());
    }

    /**
     * A real lock wait timeout on MySQL, which rolls back only the statement
     * that waited, met by the work inside a caller's transaction that catches
     * it and commits, leaves none of the work's writes, on every supported
     * Laravel version.
     *
     * @param  bool  $leavesTheSavepoint
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideSavepointHandling')]
    public function testARealLockWaitTimeoutInsideACallersTransactionLeavesNoneOfTheWorksWrites(bool $leavesTheSavepoint): void
    {
        if (DB::connection()->getDriverName() !== 'mysql') {
            self::markTestSkipped('A lock wait timeout that rolls back its statement alone is provoked on MySQL.');
        }

        if (!in_array(DB::scalar('select @@innodb_rollback_on_timeout'), [0, '0'], true)) {
            self::markTestSkipped('The server rolls back the whole transaction on a lock wait timeout.');
        }

        DB::table(self::TABLE)->insert(['id' => 1, 'value' => 1]);

        $this->handleTheSavepoint($leavesTheSavepoint);

        $other = self::otherConnection();

        $other->beginTransaction();
        $other->query('select * from ' . self::TABLE . ' where id = 1 for update');

        DB::statement('set session innodb_lock_wait_timeout = ' . self::LOCK_WAIT_TIMEOUT_SECONDS);
        DB::beginTransaction();
        DB::table(self::TABLE)->insert(['id' => 10, 'value' => 10]);

        $thrown = null;

        try {
            $this->transaction()->run(static function (): void {

                DB::table(self::TABLE)->insert(['id' => 20, 'value' => 20]);
                DB::table(self::TABLE)->where('id', 1)->update(['value' => 2]);
            });
        } catch (DeadlockException $thrown) {
            // Asserted below, beside what the caller's transaction kept.
        } finally {
            $other->rollBack();
        }

        self::assertInstanceOf(DeadlockException::class, $thrown);
        self::assertStringContainsString('Lock wait timeout exceeded', $thrown->getMessage());

        DB::commit();

        self::assertSame([1, 10], DB::table(self::TABLE)->orderBy('id')->pluck('id')->all());
    }

    /**
     * Rolling back to the work's savepoint after a concurrency failure, when
     * the database has already discarded it, as MySQL does with the whole
     * transaction after a deadlock, fails quietly, and the work's own failure
     * is thrown on; the savepoint is the one opened above the caller's level.
     *
     * @return void
     */
    public function testASavepointTheDatabaseHasAlreadyDiscardedLeavesTheWorksFailureThrownOn(): void
    {
        $failure    = new DeadlockException(self::LOCK_WAIT_TIMEOUT, 0, new \RuntimeException(self::LOCK_WAIT_TIMEOUT));
        $connection = $this->connectionFailingInside($failure, true);
        $pdo        = \Mockery::mock(\PDO::class);
        $gone       = new \PDOException('SQLSTATE[42000]: Syntax error or access violation: 1305 SAVEPOINT trans3 does not exist');

        $pdo->shouldReceive('exec')->once()->with('rollback to trans3')->andThrow($gone);
        $connection->shouldReceive('getPdo')->andReturn($pdo);

        self::assertSame($failure, $this->failureOfMockedRun($connection, static function (): void {}, 3));
    }

    /**
     * A connection whose grammar has no savepoints has none to roll back to.
     *
     * @return void
     */
    public function testAConnectionWithoutSavepointsRollsNothingBack(): void
    {
        $failure    = new DeadlockException(self::LOCK_WAIT_TIMEOUT, 0, new \RuntimeException(self::LOCK_WAIT_TIMEOUT));
        $connection = $this->connectionFailingInside($failure, false);

        $connection->shouldNotReceive('getPdo');

        self::assertSame($failure, $this->failureOfMockedRun($connection, static function (): void {}, 3));
    }

    /**
     * A failure Laravel's nested transaction did not take for a concurrency
     * failure is one Laravel has rolled back to the savepoint itself, so it is
     * not rolled back again: a savepoint of that name might be an earlier one,
     * when the nested transaction failed to open its own.
     *
     * @return void
     */
    public function testAFailureThatIsNotAConcurrencyFailureIsLeftToLaravelsRollback(): void
    {
        $failure    = new \RuntimeException('Something went wrong.');
        $connection = \Mockery::mock(Connection::class);

        $connection->shouldReceive('transactionLevel')->andReturn(2);
        $connection->shouldReceive('transaction')->once()->andThrow($failure);
        $connection->shouldNotReceive('getQueryGrammar');
        $connection->shouldNotReceive('getPdo');

        self::assertSame($failure, $this->failureOfMockedRun($connection, static function (): void {}, 3));
    }

    /**
     * A transaction the caller opened on another connection than the storage
     * one does not hold the work: it is the outermost transaction on the
     * storage connection, and is retried.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATransactionOnAnotherConnectionDoesNotStopTheRetry(): void
    {
        self::useStorageConnection();

        DB::beginTransaction();

        self::assertSame([2, null], $this->failingRun(LinkCandidatesChanged::retryWhole(), 3, 2));

        DB::rollBack();
    }

    /**
     * Fewer than one attempt is refused before the work runs, inside a caller's
     * transaction too.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testFewerThanOneAttemptIsRefused(): void
    {
        $runs = 0;
        $work = static function () use (&$runs): void {
            $runs++;
        };

        foreach ([0, -1] as $attempts) {
            $this->assertRefused($work, $attempts);
        }

        DB::beginTransaction();

        $this->assertRefused($work, 0);

        DB::rollBack();

        self::assertSame(0, $runs);
    }

    /**
     * A concurrency failure at commit, which leaves SQLite's connection inside
     * the transaction, is rolled back before the whole work is run again, so
     * the retry starts a transaction of its own and commits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACommitThatFailsOnALockIsRolledBackAndRetried(): void
    {
        $reader   = $this->useLockingConnection();
        $attempts = 0;

        $result = $this->transaction()->run(static function () use (&$attempts, $reader): int {

            $attempts++;

            if ($attempts === 2) {
                $reader->exec('COMMIT');
            }

            DB::connection(self::LOCKING)->table(self::TABLE)->where('id', 1)->update(['value' => $attempts]);

            return $attempts;
        }, 3);

        self::assertSame(2, $result);
        self::assertFalse(DB::connection(self::LOCKING)->getPdo()->inTransaction());
        self::assertSame(2, self::lockedValue());
    }

    /**
     * A commit that fails on its last attempt is rolled back before the failure
     * is rethrown, so the connection's next transaction is not started inside
     * it and commits once the lock is gone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACommitThatFailsOnItsLastAttemptIsRolledBackBeforeItIsRethrown(): void
    {
        $reader = $this->useLockingConnection();

        try {
            $this->transaction()->run(static function (): void {
                DB::connection(self::LOCKING)->table(self::TABLE)->where('id', 1)->update(['value' => 5]);
            }, 1);

            self::fail('The commit did not fail on the held lock.');
        } catch (\PDOException $failure) {
            self::assertStringContainsString('database is locked', $failure->getMessage());
        }

        self::assertFalse(DB::connection(self::LOCKING)->getPdo()->inTransaction());

        $reader->exec('COMMIT');

        $this->transaction()->run(static function (): void {
            DB::connection(self::LOCKING)->table(self::TABLE)->where('id', 1)->update(['value' => 7]);
        }, 1);

        self::assertSame(7, self::lockedValue());
    }

    /**
     * The after-commit callbacks an attempt queued before its commit failed are
     * discarded with it, so only the attempt that committed has its callbacks
     * run.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheAfterCommitCallbacksOfAnAttemptWhoseCommitFailedAreDiscarded(): void
    {
        $reader   = $this->useLockingConnection();
        $attempts = 0;
        $fired    = [];

        $this->transaction()->run(static function () use (&$attempts, &$fired, $reader): void {

            $attempts++;

            if ($attempts === 2) {
                $reader->exec('COMMIT');
            }

            self::writeLockedRowAndQueueCallback($attempts, 'attempt ' . $attempts, $fired);
        }, 3);

        self::assertSame(2, $attempts);
        self::assertSame(['attempt 2'], $fired);
    }

    /**
     * The after-commit callbacks of an attempt whose commit failed on the last
     * attempt never run, not even once the connection's next transaction
     * commits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheAfterCommitCallbacksOfACommitThatFailedOnItsLastAttemptNeverRun(): void
    {
        $reader = $this->useLockingConnection();
        $fired  = [];

        try {
            $this->transaction()->run(static function () use (&$fired): void {
                self::writeLockedRowAndQueueCallback(5, 'failed attempt', $fired);
            }, 1);

            self::fail('The commit did not fail on the held lock.');
        } catch (\PDOException $failure) {
            self::assertStringContainsString('database is locked', $failure->getMessage());
        }

        $reader->exec('COMMIT');

        DB::connection(self::LOCKING)->transaction(static function (): void {
            DB::connection(self::LOCKING)->table(self::TABLE)->where('id', 1)->update(['value' => 7]);
        });

        self::assertSame([], $fired);
        self::assertSame(7, self::lockedValue());
    }

    /**
     * Rows of `[source]`, where `source` makes a failure Laravel's detector
     * sees as a concurrency failure once the attempt has committed: an
     * after-commit callback the work queued, and a listener for the
     * connection's `committed` event.
     *
     * @return iterable<string, array{0: \Closure(\Throwable): void}>
     */
    public static function provideFailuresOnceCommitted(): iterable
    {
        yield 'after-commit callback' => [static function (\Throwable $failure): void {
            DB::afterCommit(static fn () => throw $failure);
        }];

        yield 'committed listener' => [static function (\Throwable $failure): void {
            Event::listen(TransactionCommitted::class, static fn () => throw $failure);
        }];
    }

    /**
     * A concurrency failure met once the attempt has committed, from an
     * after-commit callback or a `committed` listener, is rethrown without
     * running the work again, so the change the attempt committed is applied
     * once.
     *
     * @param  \Closure(\Throwable): void  $source
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideFailuresOnceCommitted')]
    public function testAFailureOnceTheAttemptHasCommittedIsRethrownWithoutRunningTheWorkAgain(\Closure $source): void
    {
        $failure = new \RuntimeException('Lock wait timeout exceeded; try restarting transaction');
        $runs    = 0;

        try {
            $this->transaction()->run(static function () use (&$runs, $failure, $source): void {

                $runs++;

                DB::table(self::TABLE)->insert(['id' => $runs, 'value' => $runs]);

                if ($runs !== 1) {
                    return;
                }

                $source($failure);
            }, 3);

            self::fail('The failure once the attempt had committed was not rethrown.');
        } catch (\RuntimeException $thrown) {
            self::assertSame($failure, $thrown);
        }

        self::assertSame(1, $runs);
        self::assertSame([1], DB::table(self::TABLE)->pluck('id')->all());
        self::assertSame(0, DB::transactionLevel());
    }

    /**
     * A concurrency failure met as the attempt commits, before the database has
     * committed it, as from a `committing` listener, is rolled back and the
     * whole work is run again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailureBeforeTheDatabaseCommitsIsRolledBackAndRetried(): void
    {
        $failure = new \RuntimeException('Deadlock found when trying to get lock; try restarting transaction');
        $failed  = false;

        Event::listen(TransactionCommitting::class, static function () use (&$failed, $failure): void {

            if ($failed) {
                return;
            }

            $failed = true;

            throw $failure;
        });

        $runs = 0;

        $result = $this->transaction()->run(static function () use (&$runs): int {

            $runs++;

            DB::table(self::TABLE)->insert(['id' => $runs, 'value' => $runs]);

            return $runs;
        }, 3);

        self::assertTrue($failed);
        self::assertSame(2, $result);
        self::assertSame([2], DB::table(self::TABLE)->pluck('id')->all());
    }

    /**
     * A failed attempt is rolled back to no transaction at all, a transaction
     * the work opened and left open included, before its failure is rethrown.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWhatTheWorkLeftOpenIsRolledBackWithIt(): void
    {
        $failure = new \RuntimeException('Something went wrong.');
        $thrown  = null;

        try {
            $this->transaction()->run(static function () use ($failure): void {

                DB::beginTransaction();
                DB::table(self::TABLE)->insert(['id' => 1, 'value' => 1]);

                throw $failure;
            }, 3);
        } catch (\RuntimeException $thrown) {
            // Asserted below, beside what the failed attempt left behind.
        }

        self::assertSame($failure, $thrown);
        self::assertSame(0, DB::transactionLevel());
        self::assertSame(0, DB::table(self::TABLE)->count());
    }

    /**
     * A rollback that fails too, as on a lost connection, leaves the work's own
     * failure as the one rethrown, and the work is not run again in what is
     * left of the transaction, retryable as the failure is.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARollbackThatFailsLeavesTheWorksFailureRethrownWithoutARetry(): void
    {
        $failure    = LinkCandidatesChanged::retryWhole();
        $connection = \Mockery::mock(Connection::class);
        $runs       = 0;

        $connection->shouldReceive('transactionLevel')->andReturn(0, 1);
        $connection->shouldReceive('beginTransaction')->once();
        $connection->shouldReceive('rollBack')->once()->with(0)->andThrow(new \PDOException('SQLSTATE[HY000]: General error: 2006 MySQL server has gone away'));
        $connection->shouldNotReceive('commit');

        $work = static function () use (&$runs, $failure): void {

            $runs++;

            throw $failure;
        };

        self::assertSame($failure, $this->failureOfMockedRun($connection, $work, 3));
        self::assertSame(1, $runs);
    }

    /**
     * Inside a caller's transaction, a failure Laravel wraps in a
     * `DeadlockException` it cannot itself recognise, as PostgreSQL's
     * serialisation failure, whose SQLSTATE the wrapper loses, is thrown on as
     * the query threw it, after one run, with the caller's transaction level
     * restored.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testInsideACallersTransactionAFailureLaravelCannotRecogniseWrappedIsThrownOnUnwrapped(): void
    {
        $failure = self::queryFailure('40001', self::PGSQL_SERIALIZATION_FAILURE);

        DB::beginTransaction();

        self::assertSame([1, $failure], $this->failingRun($failure, 3));
        self::assertSame(1, DB::transactionLevel());

        DB::rollBack();
    }

    /**
     * Inside a caller's transaction that Laravel retries, a serialisation
     * failure in the work reaches the caller's retry, which runs the caller's
     * whole transaction again, as it would without this package in between.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testInsideACallersRetryingTransactionASerialisationFailureIsRetriedByTheCaller(): void
    {
        $failure     = self::queryFailure('40001', self::PGSQL_SERIALIZATION_FAILURE);
        $transaction = $this->transaction();
        $attempts    = 0;

        $result = DB::transaction(static function () use (&$attempts, $failure, $transaction): int {

            $attempts++;

            DB::table(self::TABLE)->insert(['id' => $attempts, 'value' => $attempts]);

            $transaction->run(static function () use ($attempts, $failure): void {

                if ($attempts === 1) {
                    throw $failure;
                }
            });

            return $attempts;
        }, 3);

        self::assertSame(2, $result);
        self::assertSame([2], DB::table(self::TABLE)->pluck('id')->all());
    }

    /**
     * Rows of `[nested]`: the work run by the outermost run itself and by a run
     * nested in it.
     *
     * @return iterable<string, array{0: bool}>
     */
    public static function provideNesting(): iterable
    {
        yield 'outermost' => [false];

        yield 'nested' => [true];
    }

    /**
     * A real serialisation failure, which PostgreSQL raises at REPEATABLE READ
     * when another transaction has changed a row since the work's snapshot, is
     * retried from the outermost transaction, a nested run's failure included,
     * and the work's second attempt reads and writes the changed row.
     *
     * @param  bool  $nested
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideNesting')]
    public function testARealSerialisationFailureIsRetriedFromTheOutermostTransaction(bool $nested): void
    {
        if (DB::connection()->getDriverName() !== 'pgsql') {
            self::markTestSkipped('Only PostgreSQL fails a write to a row changed since the snapshot at REPEATABLE READ.');
        }

        self::useIsolationLevel('repeatable read');

        DB::table(self::TABLE)->insert(['id' => 1, 'value' => 1]);

        $other    = self::otherConnection();
        $attempts = 0;
        $read     = [];

        $work = static function () use (&$attempts, &$read, $other): void {

            $attempts++;
            $read[] = DB::table(self::TABLE)->where('id', 1)->value('value');

            if ($attempts === 1) {
                $other->exec('update ' . self::TABLE . ' set value = value + 1 where id = 1');
            }

            DB::table(self::TABLE)->where('id', 1)->increment('value', 10);
        };

        $this->transaction()->run($this->nest($work, $nested));

        self::assertSame(2, $attempts);
        self::assertSame([1, 2], $read);
        self::assertSame(12, self::valueOf(1));
    }

    /**
     * A real serialisation failure, on PostgreSQL at REPEATABLE READ, met in a
     * member's own nested transaction on the last attempt, reaches the caller
     * as the database raised it, a `QueryException` with SQLSTATE 40001 that
     * Laravel's detector recognises, not Laravel's `DeadlockException` around
     * it, and only the other transaction's write is kept.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARealSerialisationFailureOnTheLastAttemptReachesTheCallerAsTheDatabaseRaisedIt(): void
    {
        if (DB::connection()->getDriverName() !== 'pgsql') {
            self::markTestSkipped('Only PostgreSQL fails a write to a row changed since the snapshot at REPEATABLE READ.');
        }

        self::useIsolationLevel('repeatable read');

        DB::table(self::TABLE)->insert(['id' => 1, 'value' => 1]);

        $other  = self::otherConnection();
        $thrown = null;

        try {
            $this->transaction()->run(static function () use ($other): void {

                DB::table(self::TABLE)->where('id', 1)->value('value');

                $other->exec('update ' . self::TABLE . ' set value = value + 1 where id = 1');

                DB::transaction(static function (): void {
                    DB::table(self::TABLE)->where('id', 1)->increment('value', 10);
                });
            }, 1);
        } catch (\Throwable $exception) {
            $thrown = $exception;
        }

        self::assertNotNull($thrown, 'A run that failed to serialise returned.');
        $this->assertRaisedByTheDatabase($thrown);
        self::assertSame('40001', $thrown->getCode());
        self::assertSame(2, self::valueOf(1));
    }

    /**
     * A real serialisation failure in the work, run inside a caller's
     * transaction that Laravel retries on PostgreSQL at REPEATABLE READ,
     * reaches the caller's retry, and the caller's second attempt reads and
     * writes the changed row.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARealSerialisationFailureInsideACallersRetryingTransactionIsRetriedByTheCaller(): void
    {
        if (DB::connection()->getDriverName() !== 'pgsql') {
            self::markTestSkipped('Only PostgreSQL fails a write to a row changed since the snapshot at REPEATABLE READ.');
        }

        self::useIsolationLevel('repeatable read');

        DB::table(self::TABLE)->insert(['id' => 1, 'value' => 1]);

        $other       = self::otherConnection();
        $transaction = $this->transaction();
        $attempts    = 0;
        $read        = [];

        DB::transaction(static function () use (&$attempts, &$read, $other, $transaction): void {

            $attempts++;
            $read[] = DB::table(self::TABLE)->where('id', 1)->value('value');

            if ($attempts === 1) {
                $other->exec('update ' . self::TABLE . ' set value = value + 1 where id = 1');
            }

            $transaction->run(static function (): void {
                DB::table(self::TABLE)->where('id', 1)->increment('value', 10);
            });
        }, 3);

        self::assertSame(2, $attempts);
        self::assertSame([1, 2], $read);
        self::assertSame(12, self::valueOf(1));
    }

    /**
     * Rows of `[isolation level, nested]`: each isolation level, with the work
     * run by the outermost run itself and by a run nested in it.
     *
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function provideIsolationLevelsAndNesting(): iterable
    {
        foreach (self::provideIsolationLevels() as $label => [$level]) {

            yield $label => [$level, false];

            yield $label . ', nested' => [$level, true];
        }
    }

    /**
     * A real deadlock, between the work and another transaction that holds the
     * row the work wants next and waits for the row the work holds, is retried
     * from the outermost transaction, a nested run's deadlock included, and
     * both sides' writes are kept.
     *
     * @param  string  $level
     * @param  bool  $nested
     * @return void
     *
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevelsAndNesting')]
    public function testARealDeadlockIsRetriedFromTheOutermostTransaction(string $level, bool $nested): void
    {
        self::requireIsolationLevels();

        if (!function_exists('pcntl_fork')) {
            self::markTestSkipped('Provoking a deadlock needs a second process, through pcntl.');
        }

        DB::table(self::TABLE)->insert([['id' => 1, 'value' => 1], ['id' => 2, 'value' => 1]]);

        $signal = sys_get_temp_dir() . '/iam-deadlock-' . bin2hex(random_bytes(8));
        $pid    = pcntl_fork();

        if ($pid === 0) {
            self::crossFromTheOtherSide($signal, $level);
        }

        self::useIsolationLevel($level);
        self::preferThisSideAsTheDeadlockVictim();

        $observer = self::otherConnection();
        $other    = (int) self::awaitSignal($signal . '.locked');
        $attempts = 0;

        $work = static function () use (&$attempts, $signal, $observer, $other): void {

            $attempts++;

            if ($attempts > 1) {
                self::awaitSignal($signal . '.done');
            }

            DB::table(self::TABLE)->where('id', 1)->increment('value', 10);

            if ($attempts === 1) {
                touch($signal . '.cross');
                self::awaitLockWait($observer, $other);
            }

            DB::table(self::TABLE)->where('id', 2)->increment('value', 10);
        };

        try {
            $this->transaction()->run($this->nest($work, $nested));
        } finally {
            pcntl_waitpid($pid, $status);
            array_map(static fn (string $file): bool => unlink($file), glob($signal . '.*') ?: []);
        }

        self::assertSame(2, $attempts);
        self::assertSame([12, 12], [self::valueOf(1), self::valueOf(2)]);
    }

    /**
     * A real deadlock, on MySQL and PostgreSQL at READ COMMITTED and REPEATABLE
     * READ, met in a member's own nested transaction on the last attempt,
     * reaches the caller as the database raised it, a `QueryException` with its
     * SQLSTATE (and MySQL's error 1213) that Laravel's detector recognises, not
     * Laravel's `DeadlockException` around it, and only the other transaction's
     * writes are kept.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testARealDeadlockOnTheLastAttemptReachesTheCallerAsTheDatabaseRaisedIt(string $level): void
    {
        self::requireIsolationLevels();

        if (!function_exists('pcntl_fork')) {
            self::markTestSkipped('Provoking a deadlock needs a second process, through pcntl.');
        }

        DB::table(self::TABLE)->insert([['id' => 1, 'value' => 1], ['id' => 2, 'value' => 1]]);

        $signal = sys_get_temp_dir() . '/iam-deadlock-' . bin2hex(random_bytes(8));
        $pid    = pcntl_fork();

        if ($pid === 0) {
            self::crossFromTheOtherSide($signal, $level);
        }

        self::useIsolationLevel($level);
        self::preferThisSideAsTheDeadlockVictim();

        $observer = self::otherConnection();
        $other    = (int) self::awaitSignal($signal . '.locked');
        $thrown   = null;

        try {
            $this->transaction()->run(static function () use ($signal, $observer, $other): void {

                DB::transaction(static function () use ($signal, $observer, $other): void {

                    DB::table(self::TABLE)->where('id', 1)->increment('value', 10);

                    touch($signal . '.cross');
                    self::awaitLockWait($observer, $other);

                    DB::table(self::TABLE)->where('id', 2)->increment('value', 10);
                });
            }, 1);
        } catch (\Throwable $exception) {
            $thrown = $exception;
        } finally {
            self::awaitSignal($signal . '.done');
            pcntl_waitpid($pid, $status);
            array_map(static fn (string $file): bool => unlink($file), glob($signal . '.*') ?: []);
        }

        self::assertNotNull($thrown, 'A run that deadlocked returned.');
        $this->assertRaisedByTheDatabase($thrown);

        if (DB::connection()->getDriverName() === 'pgsql') {
            self::assertSame('40P01', $thrown->getCode());
        } else {
            self::assertSame('40001', $thrown->getCode());
            self::assertSame(self::MYSQL_DEADLOCK_ERROR, $thrown->errorInfo[1] ?? null);
        }

        self::assertSame([2, 2], [self::valueOf(1), self::valueOf(2)]);
    }

    /**
     * Assert that the failure reached the caller as the database raised it: a
     * `QueryException`, not Laravel's `DeadlockException` around one, that
     * Laravel's concurrency detector recognises, so the caller retries.
     *
     * @param  \Throwable  $thrown
     * @return void
     *
     * @phpstan-assert \Illuminate\Database\QueryException $thrown
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function assertRaisedByTheDatabase(\Throwable $thrown): void
    {
        self::assertNotInstanceOf(DeadlockException::class, $thrown);
        self::assertInstanceOf(QueryException::class, $thrown);
        self::assertTrue($this->app?->make(ConcurrencyErrorDetector::class)->causedByConcurrencyError($thrown));
    }

    /**
     * Resolve the transaction from the container.
     *
     * @return \SineMacula\Laravel\Iam\Transactions\CrossMemberTransaction
     */
    private function transaction(): CrossMemberTransaction
    {
        $transaction = $this->app?->make(CrossMemberTransaction::class);

        self::assertInstanceOf(CrossMemberTransaction::class, $transaction);

        return $transaction;
    }

    /**
     * Run the work through a transaction whose storage connection is the given
     * one, and return what it threw.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \Closure(): void  $work
     * @param  int  $attempts
     * @return \Throwable
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function failureOfMockedRun(Connection $connection, \Closure $work, int $attempts): \Throwable
    {
        $app      = $this->app;
        $database = \Mockery::mock(DatabaseManager::class);

        self::assertNotNull($app);

        $database->shouldReceive('connection')->andReturn($connection);

        $transaction = new CrossMemberTransaction($database, $app->make(StorageConnection::class), $app->make(RetrySettings::class), $app->make(ConcurrencyFailures::class));

        try {
            $transaction->run($work, $attempts);
        } catch (\Throwable $thrown) {
            return $thrown;
        }

        self::fail('The mocked run did not fail.');
    }

    /**
     * Return a mocked connection, inside a caller's transaction two levels
     * deep, whose nested transaction fails with the given failure, and whose
     * grammar has savepoints or not.
     *
     * @param  \Throwable  $failure
     * @param  bool  $savepoints
     * @return \Illuminate\Database\Connection&\Mockery\MockInterface
     */
    private function connectionFailingInside(\Throwable $failure, bool $savepoints): Connection
    {
        $grammar    = \Mockery::mock(Grammar::class);
        $connection = \Mockery::mock(Connection::class);

        $grammar->shouldReceive('supportsSavepoints')->andReturn($savepoints);
        $grammar->shouldReceive('compileSavepointRollBack')->with('trans3')->andReturn('rollback to trans3');

        $connection->shouldReceive('transactionLevel')->andReturn(2);
        $connection->shouldReceive('transaction')->once()->andThrow($failure);
        $connection->shouldReceive('getQueryGrammar')->andReturn($grammar);

        return $connection;
    }

    /**
     * Make the storage connection one that leaves a nested transaction's
     * savepoint in place after a concurrency failure, as Laravel before 13.40
     * does, or leave it as the installed Laravel handles it.
     *
     * @param  bool  $leavesTheSavepoint
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function handleTheSavepoint(bool $leavesTheSavepoint): void
    {
        if (!$leavesTheSavepoint) {
            return;
        }

        $database = $this->app?->make(DatabaseManager::class);

        self::assertInstanceOf(DatabaseManager::class, $database);

        SavepointLeavingConnections::replace($database, self::CONNECTION);
    }

    /**
     * Make the storage connection one on a SQLite file whose one row another
     * connection, the one returned, holds a read lock on, so a commit that
     * writes it fails with `database is locked` until that reader commits.
     *
     * @return \PDO
     */
    private function useLockingConnection(): \PDO
    {
        $this->lockingFile = (string) tempnam(sys_get_temp_dir(), 'iam-locking-');

        Config::set('database.connections.' . self::LOCKING, [
            'driver'       => 'sqlite',
            'database'     => $this->lockingFile,
            'prefix'       => '',
            'busy_timeout' => self::LOCKING_BUSY_TIMEOUT,
            'journal_mode' => 'delete',
        ]);
        Config::set('iam.storage.connection', self::LOCKING);

        $reader = new \PDO('sqlite:' . $this->lockingFile);

        $reader->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
        $reader->exec('CREATE TABLE ' . self::TABLE . ' (id INTEGER PRIMARY KEY, value INTEGER NOT NULL)');
        $reader->exec('INSERT INTO ' . self::TABLE . ' (id, value) VALUES (1, 0)');
        $reader->exec('BEGIN');

        $statement = $reader->query('SELECT * FROM ' . self::TABLE);

        self::assertNotFalse($statement);

        $statement->fetchAll();

        return $reader;
    }

    /**
     * Return the value of the locking connection's one row.
     *
     * @return int
     */
    private static function lockedValue(): int
    {
        $value = DB::connection(self::LOCKING)->table(self::TABLE)->value('value');

        self::assertIsNumeric($value);

        return (int) $value;
    }

    /**
     * Write the locking connection's one row and queue a callback, run once the
     * transaction commits, that records the label.
     *
     * @param  int  $value
     * @param  string  $label
     * @param  list<string>  $fired
     *
     * @param-out list<string>  $fired
     *
     * @return void
     */
    private static function writeLockedRowAndQueueCallback(int $value, string $label, array &$fired): void
    {
        $connection = DB::connection(self::LOCKING);

        $connection->table(self::TABLE)->where('id', 1)->update(['value' => $value]);
        $connection->afterCommit(static function () use (&$fired, $label): void {
            $fired[] = $label;
        });
    }

    /**
     * Run work that writes a row and fails until the given attempt, and return
     * how many times it ran and what was thrown (`null` when nothing was).
     *
     * @param  \Throwable  $failure
     * @param  ?int  $attempts
     * @param  ?int  $succeedsAt
     * @return array{0: int, 1: ?\Throwable}
     */
    private function failingRun(\Throwable $failure, ?int $attempts = null, ?int $succeedsAt = null): array
    {
        $runs = 0;

        try {
            $this->transaction()->run(static function () use (&$runs, $failure, $succeedsAt): void {

                $runs++;

                if ($runs !== $succeedsAt) {
                    throw $failure;
                }
            }, $attempts);
        } catch (\Throwable $thrown) {
            return [$runs, $thrown];
        }

        return [$runs, null];
    }

    /**
     * Assert that the run is refused for the attempts before the work runs.
     *
     * @param  \Closure(): void  $work
     * @param  int  $attempts
     * @return void
     *
     * @throws \Throwable
     */
    private function assertRefused(\Closure $work, int $attempts): void
    {
        try {
            $this->transaction()->run($work, $attempts);
        } catch (\InvalidArgumentException $refusal) {
            self::assertSame(sprintf('A cross-member transaction is attempted at least once, the first included: [%d] attempts given.', $attempts), $refusal->getMessage());

            return;
        }

        self::fail('A run of ' . $attempts . ' attempts was not refused.');
    }

    /**
     * Return the work, or work that runs it through a run nested in the
     * outermost one.
     *
     * @param  \Closure(): void  $work
     * @param  bool  $nested
     * @return \Closure(): void
     */
    private function nest(\Closure $work, bool $nested): \Closure
    {
        if (!$nested) {
            return $work;
        }

        $transaction = $this->transaction();

        return static function () use ($transaction, $work): void {
            $transaction->run($work);
        };
    }

    /**
     * Make the storage connection one named `storage`, on the same database as
     * the default connection's settings.
     *
     * @return void
     */
    private static function useStorageConnection(): void
    {
        Config::set('database.connections.storage', Config::get('database.connections.' . self::CONNECTION));
        Config::set('iam.storage.connection', 'storage');
    }

    /**
     * On PostgreSQL, where the side whose deadlock timeout ends first finds the
     * deadlock and is rolled back, end the work's side's first.
     *
     * @return void
     */
    private static function preferThisSideAsTheDeadlockVictim(): void
    {
        if (DB::connection()->getDriverName() !== 'pgsql') {
            return;
        }

        DB::statement('set deadlock_timeout = \'' . self::WORK_DEADLOCK_TIMEOUT . '\'');
    }

    /**
     * In the forked process, on a connection of its own: lock row 2, the
     * heavier side, then, once the work holds row 1, wait for row 1, which the
     * work's rollback grants, and commit. The process ends itself without
     * running any shutdown, which would close the parent's connections.
     *
     * @param  string  $signal
     * @param  string  $level
     * @return never
     */
    private static function crossFromTheOtherSide(string $signal, string $level): never
    {
        try {
            $other = self::otherConnection();
            $pgsql = $other->getAttribute(\PDO::ATTR_DRIVER_NAME) === 'pgsql';

            if ($pgsql) {
                $other->exec('set deadlock_timeout = \'' . self::OTHER_DEADLOCK_TIMEOUT . '\'');
            }

            $other->exec(($pgsql ? 'set session characteristics as transaction isolation level ' : 'set session transaction isolation level ') . $level);
            $other->beginTransaction();

            for ($id = 1000; $id < 1000 + self::WEIGHT_ROWS; $id++) {
                $other->exec('insert into ' . self::TABLE . ' (id, value) values (' . $id . ', 0)');
            }

            $other->exec('update ' . self::TABLE . ' set value = value + 1 where id = 2');

            $statement = $other->query($pgsql ? 'select pg_backend_pid()' : 'select connection_id()');
            $session   = $statement === false ? null : $statement->fetchColumn();

            file_put_contents($signal . '.locked', is_int($session) || is_string($session) ? (string) $session : '');

            self::awaitSignal($signal . '.cross');

            $other->exec('update ' . self::TABLE . ' set value = value + 1 where id = 1');
            $other->commit();

            touch($signal . '.done');
        } finally {
            posix_kill(posix_getpid(), SIGKILL);
        }

        exit(1);
    }

    /**
     * Return the value the row with the given key holds.
     *
     * @param  int  $id
     * @return int
     */
    private static function valueOf(int $id): int
    {
        $value = DB::table(self::TABLE)->where('id', $id)->value('value');

        self::assertIsNumeric($value);

        return (int) $value;
    }

    /**
     * Wait until the other side's session is waiting for a row lock.
     *
     * @param  \PDO  $observer
     * @param  int  $session
     * @return void
     */
    private static function awaitLockWait(\PDO $observer, int $session): void
    {
        $query = $observer->getAttribute(\PDO::ATTR_DRIVER_NAME) === 'pgsql'
            ? 'select count(*) from pg_stat_activity where pid = ? and wait_event_type = \'Lock\''
            : 'select count(*) from information_schema.innodb_trx where trx_mysql_thread_id = ? and trx_state = \'LOCK WAIT\'';

        $statement = $observer->prepare($query);
        $deadline  = microtime(true) + self::SIGNAL_TIMEOUT_SECONDS;

        do {
            $statement->execute([$session]);

            if ((int) $statement->fetchColumn() > 0) {
                return;
            }

            usleep(self::LOCK_WAIT_POLL_MICROSECONDS);
        } while (microtime(true) < $deadline);

        self::fail('The other side never waited for the row the work holds.');
    }

    /**
     * Wait for the other side's signal file and return what it holds.
     *
     * @param  string  $file
     * @return string
     */
    private static function awaitSignal(string $file): string
    {
        $deadline = microtime(true) + self::SIGNAL_TIMEOUT_SECONDS;

        while (!is_file($file)) {

            if (microtime(true) > $deadline) {
                self::fail('No signal at ' . $file . '.');
            }

            usleep(5000);
        }

        return (string) file_get_contents($file);
    }

    /**
     * Open a second connection, of the test's own, to the database the default
     * connection is on, outside Laravel, committing every statement it runs
     * outside a transaction.
     *
     * @return \PDO
     */
    private static function otherConnection(): \PDO
    {
        /** @var array{driver: string, host: string, port: string, database: string, username: string, password: string} $config */
        $config = Config::get('database.connections.' . self::CONNECTION);

        return new \PDO(
            sprintf('%s:host=%s;port=%s;dbname=%s', $config['driver'], $config['host'], $config['port'], $config['database']),
            $config['username'],
            $config['password'],
            [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION],
        );
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

        return new QueryException('testing', 'update `rows` set `value` = ?', [1], $failure);
    }
}
