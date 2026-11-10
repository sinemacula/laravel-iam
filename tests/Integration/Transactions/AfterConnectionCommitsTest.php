<?php

declare(strict_types = 1);

namespace Tests\Integration\Transactions;

use Illuminate\Container\Container;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Connection;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Iam\Transactions\AfterConnectionCommits;
use Tests\TestCase;

/**
 * Integration tests for deferring work until the transactions open on one
 * connection have committed: it runs at once with none open, once the outermost
 * commits and not when a savepoint does, and only once every callback queued on
 * the transaction has run, one queued after it included, never when the
 * outermost or the savepoint it was queued in rolls back, and a transaction
 * open on another connection neither delays nor drops it; what it throws
 * propagates from the commit once every callback has run; a commit callback
 * that fails, before it or after it, leaves it held for the end of the unit of
 * work, or for the connection's next outermost commit, never a savepoint's, and
 * the end of the unit of work leaves a connection with a transaction open, runs
 * nothing rolled back, and reports what the work throws; without Laravel's
 * transactions manager it runs at once, and without an events dispatcher on the
 * connection it runs from its own callback.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AfterConnectionCommits::class)]
final class AfterConnectionCommitsTest extends TestCase
{
    /** @var string Another connection, with transactions of its own. */
    private const string OTHER = 'other';

    /** @var int How many times the work has run. */
    private int $runs = 0;

    /** @var list<string> What ran, in the order it ran. */
    private array $ran = [];

    /**
     * With no transaction open on the connection, the work runs at once.
     *
     * @return void
     */
    public function testWithNoTransactionOpenTheWorkRunsAtOnce(): void
    {
        $this->deferred()->run(self::connection(), $this->work());

        self::assertSame(1, $this->runs);
    }

    /**
     * Queued inside a savepoint, the work runs once the outermost transaction
     * commits, not when the savepoint does, and once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheWorkRunsOnceTheOutermostTransactionCommits(): void
    {
        $connection = self::connection();

        $connection->transaction(function () use ($connection): void {

            $connection->transaction(fn () => $this->deferred()->run($connection, $this->work()));

            self::assertSame(0, $this->runs, 'The work ran when the savepoint committed.');
        });

        self::assertSame(1, $this->runs);
    }

    /**
     * The work runs only once every callback queued on the transaction has run,
     * one queued after it included, so work that begins a transaction of its
     * own begins none while a callback still waits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheWorkRunsOnceEveryCallbackOfTheCommitHasRun(): void
    {
        $connection = self::connection();

        $connection->transaction(function () use ($connection): void {

            $this->deferred()->run($connection, $this->noted('work'));
            $connection->afterCommit($this->noted('callback'));
        });

        self::assertSame(['callback', 'work'], $this->ran);
    }

    /**
     * What the work throws propagates from the commit, once the transaction has
     * committed and every callback queued on it has run.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWhatTheWorkThrowsPropagatesOnceTheCommitHasFinished(): void
    {
        $connection = self::connection();
        $failure    = new \RuntimeException('The work failed.');

        try {
            $connection->transaction(function () use ($connection, $failure): void {

                $this->deferred()->run($connection, static fn () => throw $failure);
                $connection->afterCommit($this->noted('callback'));
            });

            self::fail('The work\'s failure did not propagate.');
        } catch (\RuntimeException $exception) {
            self::assertSame($failure, $exception);
        }

        self::assertSame(0, $connection->transactionLevel());
        self::assertSame(['callback'], $this->ran);
    }

    /**
     * A connection with no events dispatcher fires no commit event, so the
     * callback runs the work itself, before a callback queued after it, and
     * holds nothing for a later commit to run again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithoutAnEventsDispatcherTheCallbackRunsTheWork(): void
    {
        $connection = self::connection();
        $events     = $connection->getEventDispatcher() ?? self::fail('The connection has no events dispatcher.');

        $connection->unsetEventDispatcher();

        try {
            $connection->transaction(function () use ($connection): void {

                $this->deferred()->run($connection, $this->noted('work'));
                $connection->afterCommit($this->noted('callback'));
            });
        } finally {
            $connection->setEventDispatcher($events);
        }

        $connection->transaction(static fn (): null => null);

        self::assertSame(['work', 'callback'], $this->ran, 'The work was held as well as run.');
    }

    /**
     * The work is dropped when the transaction it was queued in rolls back, the
     * outermost or a savepoint the outermost outlives.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheWorkIsDroppedWhenItsTransactionRollsBack(): void
    {
        $connection = self::connection();

        $connection->beginTransaction();
        $this->deferred()->run($connection, $this->work());
        $connection->rollBack();

        $connection->transaction(function () use ($connection): void {

            $connection->beginTransaction();
            $this->deferred()->run($connection, $this->work());
            $connection->rollBack();
        });

        self::assertSame(0, $this->runs);
    }

    /**
     * A transaction open on another connection neither delays the work, with
     * none open on the connection, nor takes it: rolled back, it leaves the
     * work queued on the connection's own transaction, which runs it once it
     * commits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnotherConnectionsTransactionNeitherDelaysNorTakesTheWork(): void
    {
        $connection = self::connection();
        $other      = DB::connection(self::OTHER);

        $other->beginTransaction();
        $this->deferred()->run($connection, $this->work());

        self::assertSame(1, $this->runs, 'The work waited for another connection.');

        $connection->transaction(function () use ($connection, $other): void {

            $this->deferred()->run($connection, $this->work());
            $other->rollBack();
            $other->beginTransaction();
        });

        $other->rollBack();

        self::assertSame(2, $this->runs);
    }

    /**
     * Without Laravel's transactions manager bound, or with something else
     * bound in its place, there is no transaction to wait for, and the work
     * runs at once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithoutATransactionsManagerTheWorkRunsAtOnce(): void
    {
        $connection = self::connection();
        $current    = Container::getInstance();
        $elsewhere  = new Container;

        $elsewhere->instance('db.transactions', new \stdClass);

        $connection->transaction(function () use ($connection, $current, $elsewhere): void {

            try {
                Container::setInstance(new Container);
                $this->deferred()->run($connection, $this->work());

                Container::setInstance($elsewhere);
                $this->deferred()->run($connection, $this->work());
            } finally {
                Container::setInstance($current);
            }

            self::assertSame(2, $this->runs);
        });
    }

    /**
     * Rows of `[before]`: whether the failing callback is queued before the
     * work, or after it.
     *
     * @return iterable<string, array{0: bool}>
     */
    public static function provideFailingCallbacks(): iterable
    {
        yield 'a callback queued before the work' => [true];

        yield 'a callback queued after the work' => [false];
    }

    /**
     * A commit callback that fails, queued before the work or after it, stops
     * Laravel running the rest and firing the commit event, so the failure
     * propagates from the commit with the work still held; the end of the unit
     * of work runs it, once.
     *
     * @param  bool  $before
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideFailingCallbacks')]
    public function testAFailingCallbackLeavesTheWorkForTheEndOfTheUnitOfWork(bool $before): void
    {
        $connection = self::connection();
        $failure    = new \RuntimeException('A callback failed.');

        try {
            $connection->transaction(function () use ($connection, $failure, $before): void {

                if ($before) {
                    $connection->afterCommit(static fn () => throw $failure);
                }

                $this->deferred()->run($connection, $this->work());

                if ($before) {
                    return;
                }

                $connection->afterCommit(static fn () => throw $failure);
            });

            self::fail('The callback\'s failure did not propagate.');
        } catch (\RuntimeException $exception) {
            self::assertSame($failure, $exception);
        }

        self::assertSame(0, $connection->transactionLevel());
        self::assertSame(0, $this->runs, 'The work ran before the commit had finished.');

        $this->deferred()->settle();
        $this->deferred()->settle();

        self::assertSame(1, $this->runs);
    }

    /**
     * Work a failed commit left held is released by the connection's next
     * outermost commit, never by a savepoint's commit inside it, so it never
     * runs inside a transaction that may still roll back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testLeftoverWorkWaitsForTheNextOutermostCommit(): void
    {
        $connection = self::connection();

        $this->leaveHeld($connection, $this->noted('work'));

        $connection->transaction(function () use ($connection): void {

            $connection->transaction(static fn (): null => null);

            self::assertSame([], $this->ran, 'A savepoint\'s commit released the work.');
        });

        self::assertSame(['work'], $this->ran);
    }

    /**
     * The end of the unit of work leaves the work held for a connection that
     * still has a transaction open, which releases it once it commits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheEndOfTheUnitOfWorkLeavesAConnectionWithATransactionOpen(): void
    {
        $connection = self::connection();

        $this->leaveHeld($connection, $this->work());

        $connection->beginTransaction();
        $this->deferred()->settle();

        self::assertSame(0, $this->runs, 'The work ran inside a transaction still open.');

        $connection->commit();

        self::assertSame(1, $this->runs);
    }

    /**
     * Work whose transaction rolled back is never run by the end of the unit of
     * work.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheEndOfTheUnitOfWorkRunsNothingRolledBack(): void
    {
        $connection = self::connection();

        $connection->beginTransaction();
        $this->deferred()->run($connection, $this->work());
        $connection->rollBack();

        $this->deferred()->settle();

        self::assertSame(0, $this->runs);
    }

    /**
     * What the work throws at the end of the unit of work is reported, the
     * caller's own work being over, and the work held for every other
     * connection still runs.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheEndOfTheUnitOfWorkReportsWhatTheWorkThrows(): void
    {
        $connection = self::connection();
        $other      = DB::connection(self::OTHER);
        $failure    = new \RuntimeException('The work failed.');
        $handler    = \Mockery::mock(ExceptionHandler::class);

        self::assertInstanceOf(Connection::class, $other);

        $handler->expects('report')->once()->with($failure);

        $this->app?->instance(ExceptionHandler::class, $handler);

        $this->leaveHeld($connection, static fn () => throw $failure);
        $this->leaveHeld($other, $this->noted('other'));

        $this->deferred()->settle();

        self::assertSame(['other'], $this->ran);
    }

    /**
     * Declare the other connection, on an in-memory SQLite database of its own.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        Config::set('database.connections.' . self::OTHER, ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
    }

    /**
     * Queue the work on a transaction of the connection whose commit fails in a
     * callback queued after it, so the commit finishes with the work held.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \Closure(): void  $work
     * @return void
     *
     * @throws \Throwable
     */
    private function leaveHeld(Connection $connection, \Closure $work): void
    {
        try {
            $connection->transaction(function () use ($connection, $work): void {

                $this->deferred()->run($connection, $work);

                $connection->afterCommit(static fn () => throw new \LogicException('A callback failed.'));
            });
        } catch (\LogicException) {
            return;
        }

        self::fail('The callback did not fail.');
    }

    /**
     * The helper, as the container builds it.
     *
     * @return \SineMacula\Laravel\Iam\Transactions\AfterConnectionCommits
     */
    private function deferred(): AfterConnectionCommits
    {
        return $this->app?->make(AfterConnectionCommits::class) ?? self::fail('The application has not booted.');
    }

    /**
     * Work that counts each time it runs.
     *
     * @return \Closure(): void
     */
    private function work(): \Closure
    {
        return function (): void {
            $this->runs++;
        };
    }

    /**
     * Work that notes its name each time it runs.
     *
     * @param  string  $name
     * @return \Closure(): void
     */
    private function noted(string $name): \Closure
    {
        return function () use ($name): void {
            $this->ran[] = $name;
        };
    }

    /**
     * The test's connection.
     *
     * @return \Illuminate\Database\Connection
     */
    private static function connection(): Connection
    {
        $connection = DB::connection(self::CONNECTION);

        self::assertInstanceOf(Connection::class, $connection);

        return $connection;
    }
}
