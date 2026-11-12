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
 * Integration tests for listing one connection's open transactions.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConnectionTransactions::class)]
final class ConnectionTransactionsTest extends TestCase
{
    /** @var string The second connection, whose transactions are never listed. */
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
     * With no transactions manager bound, no transaction is listed open.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithNoTransactionsManagerNoneIsOpen(): void
    {
        $app = $this->app ?? self::fail('The application has not booted.');

        DB::transaction(static function () use ($app): void {

            unset($app['db.transactions']);

            self::assertSame([], ConnectionTransactions::open(null));
        });
    }
}
