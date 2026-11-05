<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversNothing;

/**
 * What a budget itself promises: it counts reads and writes exactly, and every
 * transaction or savepoint begun, committed and rolled back, only while the
 * path runs, and refuses a statement that is neither a read nor a write. It
 * runs the base class and none of the package's source, so it covers nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class QueryBudgetContractTest extends PerformanceContractTestCase
{
    /**
     * A select is a read, and an insert, an update and a delete are writes.
     *
     * @return void
     */
    public function testReadsAndWritesAreCountedApart(): void
    {
        $result = $this->assertQueryBudget(1, 3, static function (): string {

            DB::table(self::TABLE)->insert(['value' => 1]);
            DB::table(self::TABLE)->update(['value' => 2]);
            DB::table(self::TABLE)->count();
            DB::table(self::TABLE)->delete();

            return 'answered';
        });

        self::assertSame('answered', $result);
    }

    /**
     * Every transaction and savepoint the path begins, commits or rolls back is
     * counted, though none logs a query.
     *
     * @return void
     */
    public function testTransactionsAndSavepointsAreCountedByWhatBecameOfThem(): void
    {
        $this->assertQueryBudget(0, 1, static function (): void {

            DB::transaction(static function (): void {

                DB::transaction(static fn (): bool => DB::table(self::TABLE)->insert(['value' => 1]));

                self::rollBackASavepoint();
            });
        }, begins: 3, commits: 2, rollbacks: 1);
    }

    /**
     * A transaction the path did not expect fails its budget, and is named in
     * the listing.
     *
     * @return void
     */
    public function testAnUnexpectedTransactionFailsAndIsListed(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessageMatches('/1\. \[testing\] begin a transaction or savepoint\n2\. \[testing\] commit a transaction or release a savepoint/');

        $this->assertQueryBudget(0, 0, static fn (): null => DB::transaction(static fn (): null => null));
    }

    /**
     * A statement before or after the path is no part of its budget.
     *
     * @return void
     */
    public function testOnlyThePathIsCounted(): void
    {
        DB::table(self::TABLE)->count();

        $this->assertQueryBudget(0, 0, static fn (): null => null);

        DB::table(self::TABLE)->count();

        $this->assertQueryBudget(1, 0, static fn (): int => DB::table(self::TABLE)->count());
    }

    /**
     * A count other than the budget fails, and names every statement made.
     *
     * @return void
     */
    public function testAnotherCountFailsAndListsTheStatements(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessageMatches('/1\. \[testing\] select count\(\*\)/');

        $this->assertQueryBudget(0, 0, static fn (): int => DB::table(self::TABLE)->count());
    }

    /**
     * A statement that is neither a read nor a write fails whatever the counts.
     *
     * @return void
     */
    public function testAStatementNobodyClassifiedFails(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('A statement is neither a read nor a write');

        $this->assertQueryBudget(0, 0, static fn (): bool => DB::statement('create index iam_budget_rows_value on ' . self::TABLE . ' (value)'));
    }

    /**
     * Open a savepoint whose work fails, so it is rolled back, and swallow the
     * failure.
     *
     * @return void
     *
     * @throws \Throwable
     */
    private static function rollBackASavepoint(): void
    {
        try {
            DB::transaction(static function (): never {
                throw new \RuntimeException('Rolled back.');
            });
        } catch (\RuntimeException) {
            // The savepoint is rolled back, and its failure is the path's own
            // to swallow.
        }
    }
}
