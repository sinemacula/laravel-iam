<?php

declare(strict_types = 1);

namespace Tests\Integration\Audit;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\AuditLogServiceProvider;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException;
use SineMacula\Laravel\AuditLog\Querying\Enums\ReadRefusal;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Transactions\CrossMemberTransaction;
use Tests\Concerns\MigratesAuditLog;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\TestCase;

/**
 * Integration tests for reading the audit trail around a change that spans
 * members (IAM-9.9): inside the transaction this package opens on the storage
 * connection (`Iam::transaction()`, IAM-11.1), audit-log refuses a read before
 * anything is queried, naming the connection, since the read's record, or a row
 * it would show, could still be rolled back; the same read once the transaction
 * has committed is let in. The change itself is untouched by the refusal it
 * caught: what it wrote commits. Audit-log's tables are created from its own
 * migrations, on the storage connection, beside the members'.
 *
 * The refusal is audit-log's, and holds only while audit-log's storage
 * connection (or, under the outbox, its outbox connection) is the storage
 * connection, or its store joins a transaction open there: audit-log checks
 * only the connections it acknowledges a record on, and this package aligns no
 * key of audit-log's. With audit-log storing on a connection of its own, the
 * same read inside the transaction is let in and queried, which the last test
 * pins; IAM-9.9 then rests on this package never reading the trail itself (the
 * decision `audit-mapping.md` records).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CrossMemberTransaction::class)]
final class TrailReadsTest extends TestCase
{
    use MigratesAuditLog, RunsAtIsolationLevels, SignsInPeople;

    /** @var string The connection audit-log stores on when the trail is kept apart. */
    private const string AUDIT_CONNECTION = 'audit';

    /**
     * A read of the trail inside a cross-member transaction is refused before
     * anything is queried, naming the storage connection, and the transaction's
     * own work still commits.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAReadInsideACrossMemberTransactionIsRefused(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person  = $this->createPerson();
        $queries = 0;
        $refusal = null;

        Iam::transaction(static function () use ($person, &$queries, &$refusal): void {

            $person->forceFill(['name' => 'Grace Hopper'])->save();

            DB::listen(static function () use (&$queries): void {
                $queries++;
            });

            try {
                AuditLog::trail()->visibleTo($person)->count();
            } catch (AuditReadRefusedException $refused) {
                $refusal = $refused;
            }
        });

        self::assertInstanceOf(AuditReadRefusedException::class, $refusal);
        self::assertSame(ReadRefusal::IN_TRANSACTION, $refusal->reason);
        self::assertSame(self::CONNECTION, $refusal->connection);
        self::assertSame(0, $queries);
        self::assertSame('Grace Hopper', $person->fresh()?->name);
    }

    /**
     * A refusal the work lets propagate rolls the whole change back, as any
     * failure of a cross-member transaction does.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testARefusalLeftToPropagateRollsTheChangeBack(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person = $this->createPerson();

        try {
            Iam::transaction(static function () use ($person): void {

                $person->forceFill(['name' => 'Grace Hopper'])->save();

                AuditLog::trail()->visibleTo($person)->count();
            });

            self::fail('The read was not refused.');
        } catch (AuditReadRefusedException $refused) {
            self::assertSame(ReadRefusal::IN_TRANSACTION, $refused->reason);
        }

        self::assertSame(0, DB::connection()->transactionLevel());
        self::assertSame('Ada Lovelace', $person->fresh()?->name);
    }

    /**
     * With audit-log storing on a connection of its own, which the application
     * may choose and this package never aligns, a read inside a cross-member
     * transaction is not refused: audit-log checks only its own connections,
     * none of which holds the transaction, so the read is queried there, and
     * the transaction's work still commits.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAReadOnAnAuditConnectionOfItsOwnIsLetIn(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $this->storeTheTrailApart();

        $person  = $this->createPerson();
        $queries = [];
        $count   = null;

        Iam::transaction(static function () use ($person, &$queries, &$count): void {

            $person->forceFill(['name' => 'Grace Hopper'])->save();

            DB::listen(static function (QueryExecuted $query) use (&$queries): void {
                $queries[] = $query->connectionName;
            });

            $count = AuditLog::trail()->visibleTo($person)->count();
        });

        self::assertIsInt($count);
        self::assertContains(self::AUDIT_CONNECTION, $queries);
        self::assertNotContains(self::CONNECTION, $queries);
        self::assertSame('Grace Hopper', $person->fresh()?->name);
    }

    /**
     * The same read once the transaction has committed is let in.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testTheSameReadAfterTheCommitIsLetIn(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person = $this->createPerson();

        Iam::transaction(static function () use ($person): void {

            $person->forceFill(['name' => 'Grace Hopper'])->save();
        });

        self::assertIsInt(AuditLog::trail()->visibleTo($person)->count());
    }

    /**
     * Have audit-log store on a connection of its own, to the same database as
     * the storage connection, with audit-log's tables created there (on SQLite
     * in memory, a second connection is a database of its own).
     *
     * @return void
     */
    private function storeTheTrailApart(): void
    {
        $config = $this->app?->make('config') ?? self::fail('The application has not booted.');

        $config->set('database.connections.' . self::AUDIT_CONNECTION, $config->get('database.connections.' . self::CONNECTION));
        $config->set('audit-log.storage.connection', self::AUDIT_CONNECTION);

        $file = (new \ReflectionClass(AuditLogServiceProvider::class))->getFileName();

        self::assertIsString($file);

        self::assertSame(0, Artisan::call('migrate', ['--database' => self::AUDIT_CONNECTION, '--path' => dirname($file, 2) . '/database/migrations', '--realpath' => true]));
    }
}
