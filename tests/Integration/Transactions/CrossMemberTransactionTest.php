<?php

declare(strict_types = 1);

namespace Tests\Integration\Transactions;

use Illuminate\Contracts\Database\ConcurrencyErrorDetector;
use Illuminate\Database\DeadlockException;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Iam\Transactions\CrossMemberTransaction;
use SineMacula\Laravel\Sso\Exceptions\LinkCandidatesChanged;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\TestCase;

/**
 * Integration tests for the cross-member transaction: retried on a concurrency
 * failure at the outermost level only.
 *
 * The real serialisation failure and deadlock run on PostgreSQL and MySQL only.
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

    /** @var string The message PostgreSQL fails a transaction that cannot be serialised with. */
    private const string PGSQL_SERIALIZATION_FAILURE = 'SQLSTATE[40001]: Serialization failure: 7 ERROR:  could not serialize access due to concurrent update';

    /** @var string The message MySQL fails a deadlock victim with. */
    private const string MYSQL_DEADLOCK = 'SQLSTATE[40001]: Serialization failure: 1213 Deadlock found when trying to get lock; try restarting transaction';

    /** @var int How many rows the other side writes first, so MySQL, which rolls back the lighter side, picks the work's. */
    private const int WEIGHT_ROWS = 20;

    /** @var int How long either side waits for the other, in seconds. */
    private const int SIGNAL_TIMEOUT_SECONDS = 10;

    /** @var int How long to wait between looks at the other side's session, beyond MySQL's 0.1s `innodb_trx` cache. */
    private const int LOCK_WAIT_POLL_MICROSECONDS = 150000;

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
    }

    /**
     * The work runs in one transaction on the storage connection, not the
     * default one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheWorkRunsInOneTransactionOnTheStorageConnection(): void
    {
        Config::set('database.connections.storage', Config::get('database.connections.' . self::CONNECTION));
        Config::set('iam.storage.connection', 'storage');

        $levels = $this->transaction()->run(static fn (): array => [DB::connection('storage')->transactionLevel(), DB::connection()->transactionLevel()]);

        self::assertSame([1, 0], $levels);
        self::assertSame(0, DB::connection('storage')->transactionLevel());
    }

    /**
     * Rows of `[failure]` the whole work is retried after.
     *
     * @return iterable<string, array{0: \Throwable}>
     */
    public static function provideRetryableFailures(): iterable
    {
        yield 'deadlock' => [self::queryFailure(self::MYSQL_DEADLOCK)];

        $serialization = self::queryFailure(self::PGSQL_SERIALIZATION_FAILURE);

        yield 'serialisation failure from a nested transaction' => [new DeadlockException($serialization->getMessage(), 0, $serialization)];

        yield 'link candidates changed' => [LinkCandidatesChanged::retryWhole()];

        yield 'a concurrency failure wrapped' => [new \RuntimeException('Redemption failed.', 0, LinkCandidatesChanged::retryWhole())];
    }

    /**
     * After a concurrency failure the whole work runs again, and only the last
     * attempt's writes are kept.
     *
     * @param  \Throwable  $failure
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideRetryableFailures')]
    public function testTheWholeWorkIsRetriedAfterAConcurrencyFailure(\Throwable $failure): void
    {
        Config::set('iam.transactions.attempts', 3);

        $attempts = 0;

        $work = static function () use (&$attempts, $failure): int {

            $attempts++;

            DB::table(self::TABLE)->insert(['id' => $attempts, 'value' => $attempts]);

            if ($attempts < 3) {
                throw $failure;
            }

            return $attempts;
        };

        self::assertSame(3, $this->transaction()->run($work));
        self::assertSame([3], DB::table(self::TABLE)->pluck('id')->all());
    }

    /**
     * After the given attempts, or 3 with none configured, the last failure is
     * rethrown as one Laravel's detector recognises.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheLastAttemptsFailureIsRethrownAsAConcurrencyFailure(): void
    {
        Config::set('iam.transactions', []);

        $failure = LinkCandidatesChanged::retryWhole();

        foreach ([[null, 3], [2, 2], [1, 1]] as [$given, $expected]) {

            [$attempts, $thrown] = $this->failingRun($failure, $given);

            self::assertSame($expected, $attempts);
            self::assertInstanceOf(DeadlockException::class, $thrown);
            self::assertSame(40001, $thrown->getCode());
            self::assertSame($failure, $thrown->getPrevious());
            self::assertTrue($this->app?->make(ConcurrencyErrorDetector::class)->causedByConcurrencyError($thrown));
        }

        self::assertSame(0, DB::table(self::TABLE)->count());
    }

    /**
     * A failure with no concurrency failure in its chain is rethrown at once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailureThatIsNotAConcurrencyFailureIsRethrownAtOnce(): void
    {
        $failure = new \RuntimeException('Something went wrong.', 0, new \LogicException('Its cause.'));

        self::assertSame([1, $failure], $this->failingRun($failure, 3));
        self::assertSame(0, DB::table(self::TABLE)->count());
    }

    /**
     * A failure once the attempt has committed is rethrown without running the
     * work again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailureAfterTheCommitIsNotRetried(): void
    {
        $failure  = self::queryFailure(self::MYSQL_DEADLOCK);
        $attempts = 0;
        $thrown   = null;

        try {
            $this->transaction()->run(static function () use (&$attempts, $failure): void {

                $attempts++;

                DB::table(self::TABLE)->insert(['id' => $attempts, 'value' => $attempts]);
                DB::afterCommit(static fn () => throw $failure);
            }, 3);
        } catch (\Throwable $exception) {
            $thrown = $exception;
        }

        self::assertSame($failure, $thrown);
        self::assertSame(1, $attempts);
        self::assertSame([1], DB::table(self::TABLE)->pluck('id')->all());
    }

    /**
     * Inside the caller's transaction the work runs once, and its failure is
     * rethrown with the caller's still open.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testInsideACallersTransactionTheWorkRunsOnceAndItsFailureIsRethrown(): void
    {
        DB::beginTransaction();
        DB::table(self::TABLE)->insert(['id' => 100, 'value' => 100]);

        $failure = new \RuntimeException('Something went wrong.');

        self::assertSame([1, $failure], $this->failingRun($failure, 3));
        self::assertSame([100], DB::table(self::TABLE)->pluck('id')->all());

        [$attempts, $thrown] = $this->failingRun(LinkCandidatesChanged::retryWhole(), 3);

        self::assertSame(1, $attempts);
        self::assertTrue($this->app?->make(ConcurrencyErrorDetector::class)->causedByConcurrencyError($thrown));
        self::assertSame(1, DB::transactionLevel());

        DB::rollBack();
    }

    /**
     * A serialisation failure inside the caller's retrying transaction reaches
     * the caller's retry, which Laravel's nesting alone would hide by dropping
     * the SQLSTATE.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testInsideACallersRetryingTransactionASerialisationFailureIsRetriedByTheCaller(): void
    {
        $failure     = self::queryFailure(self::PGSQL_SERIALIZATION_FAILURE);
        $transaction = $this->transaction();
        $attempts    = 0;

        $work = static function () use (&$attempts, $failure, $transaction): int {

            $attempts++;

            DB::table(self::TABLE)->insert(['id' => $attempts, 'value' => $attempts]);

            $transaction->run(static fn () => $attempts === 1 ? throw $failure : null);

            return $attempts;
        };

        self::assertSame(2, DB::transaction($work, 3));
        self::assertSame([2], DB::table(self::TABLE)->pluck('id')->all());
    }

    /**
     * Rows of `[given, configured]` attempts that are refused.
     *
     * @return iterable<string, array{0: ?int, 1: mixed}>
     */
    public static function provideRefusedAttempts(): iterable
    {
        yield 'none given' => [0, 3];

        yield 'none configured' => [null, 0];

        yield 'configured as text' => [null, '3'];
    }

    /**
     * Fewer than one attempt, or attempts that are no whole number, are refused
     * before the work runs.
     *
     * @param  ?int  $given
     * @param  mixed  $configured
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideRefusedAttempts')]
    public function testFewerThanOneAttemptIsRefused(?int $given, mixed $configured): void
    {
        Config::set('iam.transactions.attempts', $configured);

        $this->expectException(\InvalidArgumentException::class);

        $this->transaction()->run(static fn () => self::fail('The work ran.'), $given);
    }

    /**
     * Rows of `[nested]`: the work run by the outermost run itself, and in a
     * member's own transaction inside it.
     *
     * @return iterable<string, array{0: bool}>
     */
    public static function provideNesting(): iterable
    {
        yield 'outermost' => [false];

        yield 'in a member\'s transaction' => [true];
    }

    /**
     * A real serialisation failure on PostgreSQL at REPEATABLE READ is retried,
     * and the retry sees the other write.
     *
     * @param  bool  $nested
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideNesting')]
    public function testARealSerialisationFailureIsRetried(bool $nested): void
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

        $this->transaction()->run($nested ? static fn () => DB::transaction($work) : $work);

        self::assertSame([1, 2], $read);
        self::assertSame(12, self::valueOf(1));
    }

    /**
     * A real deadlock on MySQL or PostgreSQL is retried, and both sides' writes
     * are kept.
     *
     * @param  bool  $nested
     * @return void
     *
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    #[DataProvider('provideNesting')]
    public function testARealDeadlockIsRetried(bool $nested): void
    {
        self::requireIsolationLevels();

        if (!function_exists('pcntl_fork')) {
            self::markTestSkipped('Provoking a deadlock needs a second process, through pcntl.');
        }

        DB::table(self::TABLE)->insert([['id' => 1, 'value' => 1], ['id' => 2, 'value' => 1]]);

        $signal = sys_get_temp_dir() . '/iam-deadlock-' . bin2hex(random_bytes(8));
        $pid    = pcntl_fork();

        if ($pid === 0) {
            self::crossFromTheOtherSide($signal);
        }

        if (DB::connection()->getDriverName() === 'pgsql') {
            DB::statement('set deadlock_timeout = \'10ms\'');
        }

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
            $this->transaction()->run($nested ? static fn () => DB::transaction($work) : $work);
        } finally {
            pcntl_waitpid($pid, $status);
            array_map(static fn (string $file): bool => unlink($file), glob($signal . '.*') ?: []);
        }

        self::assertSame(2, $attempts);
        self::assertSame([12, 12], [self::valueOf(1), self::valueOf(2)]);
    }

    /**
     * Run work that fails on every attempt, and answer how many times it ran
     * and what was thrown.
     *
     * @param  \Throwable  $failure
     * @param  ?int  $attempts
     * @return array{0: int, 1: \Throwable}
     */
    private function failingRun(\Throwable $failure, ?int $attempts = null): array
    {
        $runs = 0;

        try {
            $this->transaction()->run(static function () use (&$runs, $failure): never {

                $runs++;

                DB::table(self::TABLE)->insert(['id' => $runs, 'value' => $runs]);

                throw $failure;
            }, $attempts);
        } catch (\Throwable $thrown) {
            return [$runs, $thrown];
        }
    }

    /**
     * The cross-member transaction as the application resolves it.
     *
     * @return \SineMacula\Laravel\Iam\Transactions\CrossMemberTransaction
     */
    private function transaction(): CrossMemberTransaction
    {
        return $this->app?->make(CrossMemberTransaction::class) ?? self::fail('The application has not booted.');
    }

    /**
     * In the forked process: lock row 2 behind a heavier transaction, wait for
     * the work to hold row 1, then want it.
     *
     * The process kills itself so no shutdown closes the parent's connections.
     *
     * @param  string  $signal
     * @return never
     */
    private static function crossFromTheOtherSide(string $signal): never
    {
        try {
            $other = self::otherConnection();
            $pgsql = $other->getAttribute(\PDO::ATTR_DRIVER_NAME) === 'pgsql';

            if ($pgsql) {
                $other->exec('set deadlock_timeout = \'30s\'');
            }

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
     * The value the row holds.
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
     * Wait until the other side's session waits for a row lock.
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
     * Wait for the other side's signal file and answer what it holds.
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
     * A second connection to the test database, outside Laravel, in autocommit.
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
     * The failure a query meets, with SQLSTATE 40001 as PDO's string code, as
     * Laravel throws it.
     *
     * @param  string  $message
     * @return \Illuminate\Database\QueryException
     */
    private static function queryFailure(string $message): QueryException
    {
        $failure = new \PDOException($message);

        (new \ReflectionProperty(\Exception::class, 'code'))->setValue($failure, '40001');

        return new QueryException('testing', 'update `rows` set `value` = ?', [1], $failure);
    }
}
