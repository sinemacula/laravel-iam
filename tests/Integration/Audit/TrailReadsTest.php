<?php

declare(strict_types = 1);

namespace Tests\Integration\Audit;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Access\DenyAllPolicy;
use SineMacula\Laravel\AuditLog\AuditLogServiceProvider;
use SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy;
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
 * Integration tests for reading the audit trail inside a change that spans
 * members.
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
     * Answer every read with audit-log's deny-all policy, since only whether a
     * read is let in matters.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->singleton(AuditAccessPolicy::class, DenyAllPolicy::class);
    }

    /**
     * A read inside a cross-member transaction is refused, and the
     * transaction's work still commits.
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
     * A refusal left to propagate rolls the whole change back.
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
     * With audit-log on a connection of its own, a read inside the transaction
     * is let in.
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
     * Have audit-log store on its own connection to the same database (on
     * in-memory SQLite, a separate one).
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
