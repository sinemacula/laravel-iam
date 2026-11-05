<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Database\Events\ConnectionEvent;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Events\TransactionBeginning;
use Illuminate\Database\Events\TransactionCommitted;
use Illuminate\Database\Events\TransactionRolledBack;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use Tests\TestCase;

/**
 * Shared base for the query budgets: exact read and write counts for a path,
 * rather than wall-clock assertions, which would be flaky, or upper bounds,
 * which would hide a statement that went away and let a ledger comment drift.
 *
 * Statements are recorded from every connection, and only while the path under
 * test runs. A select is a read and an insert, an update or a delete is a
 * write; anything else fails the test, so a statement nobody has classified is
 * never counted silently as one or the other. Laravel begins, commits and rolls
 * back transactions and savepoints through PDO without logging a query, so
 * those are counted apart, from the connection's transaction events: a begin
 * for every transaction or savepoint opened, a commit for every one committed
 * or released, and a rollback for every one rolled back. Each budget may write
 * to one table of its own, created before it runs and dropped after.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
abstract class PerformanceContractTestCase extends TestCase
{
    /** @var string The table a budget's path may write to. */
    protected const string TABLE = 'iam_budget_rows';

    /** @var array<class-string<\Illuminate\Database\Events\ConnectionEvent>, array{0: 'begin'|'commit'|'rollback', 1: string}> The transaction events a budget counts, with the kind each is counted as and how the listing names it. */
    private const array TRANSACTION_EVENTS = [
        TransactionBeginning::class  => ['begin', 'begin a transaction or savepoint'],
        TransactionCommitted::class  => ['commit', 'commit a transaction or release a savepoint'],
        TransactionRolledBack::class => ['rollback', 'roll back a transaction or savepoint'],
    ];

    /** @var list<array{connection: string, sql: string, kind: 'begin'|'commit'|'rollback'|null}> The statements and transaction events the path under test made, in order. */
    private array $statements = [];

    /** @var bool Whether the path under test is running. */
    private bool $capturing = false;

    /**
     * Create the budget's table and listen for statements.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Schema::dropIfExists(self::TABLE);
        Schema::create(self::TABLE, static function (Blueprint $table): void {

            $table->increments('id');
            $table->integer('value');
        });

        DB::listen(function (QueryExecuted $query): void {

            if (!$this->capturing) {
                return;
            }

            $this->statements[] = ['connection' => $query->connectionName, 'sql' => $query->sql, 'kind' => null];
        });

        Event::listen(array_keys(self::TRANSACTION_EVENTS), function (ConnectionEvent $event): void {

            if (!$this->capturing) {
                return;
            }

            [$kind, $name] = self::TRANSACTION_EVENTS[$event::class];

            $this->statements[] = ['connection' => $event->connectionName, 'sql' => $name, 'kind' => $kind];
        });
    }

    /**
     * Drop the budget's table.
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
     * Run the path and assert exactly how many reads and writes it made, and
     * how many transactions or savepoints it began, committed and rolled back.
     *
     * @template TResult
     *
     * @param  int  $reads
     * @param  int  $writes
     * @param  callable(): TResult  $callback
     * @param  int  $begins
     * @param  int  $commits
     * @param  int  $rollbacks
     * @return TResult
     */
    protected function assertQueryBudget(int $reads, int $writes, callable $callback, int $begins = 0, int $commits = 0, int $rollbacks = 0): mixed
    {
        $this->statements = [];
        $this->capturing  = true;

        try {
            $result = $callback();
        } finally {
            $this->capturing = false;
        }

        $budget = ['read' => $reads, 'write' => $writes, 'begin' => $begins, 'commit' => $commits, 'rollback' => $rollbacks];

        static::assertSame($budget, $this->counts(), "The path left its query budget.\n" . $this->listing());

        return $result;
    }

    /**
     * Whether the statement reads or writes, or null when it does neither.
     *
     * @param  string  $sql
     * @return 'read'|'write'|null
     */
    private static function kindOf(string $sql): ?string
    {
        return match (strtolower(strtok(ltrim($sql), " \t\r\n(") ?: '')) {
            'select'                     => 'read',
            'insert', 'update', 'delete' => 'write',
            default                      => null,
        };
    }

    /**
     * How many reads and writes the path made, and how many transactions or
     * savepoints it began, committed and rolled back, failing the test on a
     * statement that is neither a read nor a write.
     *
     * @return array{read: int, write: int, begin: int, commit: int, rollback: int}
     */
    private function counts(): array
    {
        $counts = ['read' => 0, 'write' => 0, 'begin' => 0, 'commit' => 0, 'rollback' => 0];

        foreach ($this->statements as $statement) {

            $kind = $statement['kind'] ?? self::kindOf($statement['sql']);

            if ($kind === null) {
                static::fail(sprintf("A statement is neither a read nor a write: [%s].\n%s", $statement['sql'], $this->listing()));
            }

            $counts[$kind]++;
        }

        return $counts;
    }

    /**
     * Every statement and transaction event the path made, in order, with its
     * connection.
     *
     * @return string
     */
    private function listing(): string
    {
        $lines = [];

        foreach ($this->statements as $index => $statement) {
            $lines[] = sprintf('%d. [%s] %s', $index + 1, $statement['connection'], $statement['sql']);
        }

        return implode("\n", $lines);
    }
}
