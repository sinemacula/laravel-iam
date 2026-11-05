<?php

declare(strict_types = 1);

namespace Tests\Performance\Transactions;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Iam\Transactions\ConcurrencyFailures;
use SineMacula\Laravel\Iam\Transactions\CrossMemberTransaction;
use SineMacula\Laravel\Iam\Transactions\RetrySettings;
use SineMacula\Laravel\Sso\Exceptions\LinkCandidatesChanged;
use Tests\Performance\PerformanceContractTestCase;

/**
 * The statements a cross-member transaction makes around the work: no query of
 * its own, and one transaction or savepoint per attempt, begun and then
 * committed or rolled back, whether it opens the transaction, runs inside the
 * caller's, or retries the work, which then makes its own statements once per
 * attempt.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CrossMemberTransaction::class)]
#[CoversClass(ConcurrencyFailures::class)]
#[CoversClass(RetrySettings::class)]
final class CrossMemberTransactionQueryBudgetTest extends PerformanceContractTestCase
{
    /**
     * Opening the transaction makes no query beyond the work's, and begins and
     * commits one transaction.
     *
     * @return void
     */
    public function testTheOutermostTransactionAddsNoStatement(): void
    {
        // Writes (1): the work's insert. Transactions: one begun and committed.
        $this->assertQueryBudget(0, 1, fn (): mixed => $this->transaction()->run(self::insertedARow(...)), begins: 1, commits: 1);

        self::assertSame(1, DB::table(self::TABLE)->count());
    }

    /**
     * Inside the caller's transaction, the work makes no query beyond its own,
     * in one savepoint begun and released.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATransactionInsideTheCallersAddsNoStatement(): void
    {
        DB::transaction(function (): void {

            // Writes (1): the work's insert. Transactions: one savepoint begun
            // and released.
            $this->assertQueryBudget(0, 1, fn (): mixed => $this->transaction()->run(self::insertedARow(...)), begins: 1, commits: 1);
        });

        self::assertSame(1, DB::table(self::TABLE)->count());
    }

    /**
     * A retried transaction makes the work's statements once per attempt and no
     * query of its own, in one transaction per attempt: each failed one rolled
     * back and the last committed.
     *
     * @return void
     */
    public function testARetryRepeatsOnlyTheWorksStatements(): void
    {
        $attempts = 0;

        $work = static function () use (&$attempts): bool {

            self::insertedARow();

            if (++$attempts < 3) {
                throw LinkCandidatesChanged::retryWhole();
            }

            return true;
        };

        // Writes (3): the work's insert in each of the three attempts, the
        // first two rolled back. Transactions: three begun, two rolled back and
        // the last committed.
        $this->assertQueryBudget(0, 3, fn (): mixed => $this->transaction()->run($work), begins: 3, commits: 1, rollbacks: 2);

        self::assertSame(1, DB::table(self::TABLE)->count());
    }

    /**
     * Write one row to the budget's table, and tell whether it was written.
     *
     * @return bool
     */
    private static function insertedARow(): bool
    {
        return DB::table(self::TABLE)->insert(['value' => 1]);
    }

    /**
     * Return the cross-member transaction.
     *
     * @return \SineMacula\Laravel\Iam\Transactions\CrossMemberTransaction
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function transaction(): CrossMemberTransaction
    {
        $transaction = $this->app?->make(CrossMemberTransaction::class);

        self::assertInstanceOf(CrossMemberTransaction::class, $transaction);

        return $transaction;
    }
}
