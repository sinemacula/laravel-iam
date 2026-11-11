<?php

declare(strict_types = 1);

namespace Tests\Integration\Transactions;

use Illuminate\Database\DatabaseTransactionRecord;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Iam\Transactions\ConnectionTransactions;
use Tests\TestCase;

/**
 * Integration tests for waiting on one connection's transactions: after-commit
 * work and rollback callbacks.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConnectionTransactions::class)]
final class ConnectionTransactionsTest extends TestCase
{
    /** @var string The second connection, whose transactions the work never waits on. */
    private const string OTHER = 'other';

    /** @var list<string> What ran, in order. */
    private array $ran = [];

    /**
     * Configure the second connection.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Config::set('database.connections.' . self::OTHER, ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
    }

    /**
     * With no transaction open on the connection, the work runs at once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithNoTransactionOpenTheWorkRunsAtOnce(): void
    {
        DB::connection(self::OTHER)->transaction(function (): void {

            ConnectionTransactions::afterCommit(null, $this->recorder('work'));

            self::assertSame(['work'], $this->ran);
        });
    }

    /**
     * The work waits for the outermost commit on its connection, not a
     * savepoint's or another connection's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheWorkRunsOnceTheConnectionsOutermostTransactionCommits(): void
    {
        DB::transaction(function (): void {

            DB::connection(self::OTHER)->transaction(function (): void {

                DB::transaction(fn () => ConnectionTransactions::afterCommit(null, $this->recorder('work')));
            });

            self::assertSame([], $this->ran);
        });

        self::assertSame(['work'], $this->ran);
    }

    /**
     * A rollback of the transaction the work waits on, or of a savepoint it was
     * queued in, drops it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARollbackDropsTheWork(): void
    {
        DB::beginTransaction();
        ConnectionTransactions::afterCommit(null, $this->recorder('outer'));
        DB::rollBack();

        DB::transaction(function (): void {

            DB::beginTransaction();
            ConnectionTransactions::afterCommit(null, $this->recorder('savepoint'));
            DB::rollBack();
        });

        self::assertSame([], $this->ran);
    }

    /**
     * The transactions open on the connection are listed outermost first, with
     * none of another connection's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheOpenTransactionsAreTheConnectionsOutermostFirst(): void
    {
        self::assertSame([], ConnectionTransactions::open(null));

        DB::transaction(static function (): void {

            DB::connection(self::OTHER)->transaction(static function (): void {

                DB::transaction(static function (): void {

                    $levels = array_map(static fn (DatabaseTransactionRecord $transaction): int => $transaction->level, ConnectionTransactions::open(null));

                    self::assertSame([1, 2], $levels);
                });
            });
        });
    }

    /**
     * A rollback callback on every open transaction fires when the outer one
     * rolls back after a savepoint committed, and the transaction rolling back
     * is no longer listed open.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARollbackCallbackOnEveryOpenTransactionFires(): void
    {
        DB::beginTransaction();

        DB::transaction(function (): void {

            foreach (ConnectionTransactions::open(null) as $transaction) {
                $transaction->addCallbackForRollback(function (): void {

                    $this->ran[] = 'rolled back with ' . count(ConnectionTransactions::open(null)) . ' open';
                });
            }
        });

        DB::rollBack();

        self::assertContains('rolled back with 0 open', $this->ran);
    }

    /**
     * With no transactions manager bound, no transaction can be waited on and
     * the work runs at once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithNoTransactionsManagerTheWorkRunsAtOnce(): void
    {
        $app = $this->app ?? self::fail('The application has not booted.');

        DB::transaction(function () use ($app): void {

            unset($app['db.transactions']);

            self::assertSame([], ConnectionTransactions::open(null));

            ConnectionTransactions::afterCommit(null, $this->recorder('work'));

            self::assertSame(['work'], $this->ran);
        });
    }

    /**
     * Work that records its name as it runs.
     *
     * @param  string  $name
     * @return \Closure(): void
     */
    private function recorder(string $name): \Closure
    {
        return function () use ($name): void {
            $this->ran[] = $name;
        };
    }
}
