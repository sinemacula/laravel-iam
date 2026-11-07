<?php

declare(strict_types = 1);

namespace Tests\Unit\Provisioning;

use Illuminate\Config\Repository;
use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Provisioning\CommittedReads;
use SineMacula\Laravel\Iam\Storage\StorageConnection;

/**
 * Unit tests for the provisioning listener's committed reads (IAM-7.1): the
 * transaction the listener opens on the storage connection is set to READ
 * COMMITTED on MySQL and MariaDB before it begins, with none open, and on
 * PostgreSQL once begun, as the outermost one; a transaction the listener runs
 * inside, a savepoint of a caller's, keeps the caller's level, as does
 * SQLite's.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CommittedReads::class)]
final class CommittedReadsTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * Rows of `[driver]`: the engines whose next transaction is set before it
     * begins.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideEnginesSetBeforeBeginning(): iterable
    {
        yield 'MySQL' => ['mysql'];

        yield 'MariaDB' => ['mariadb'];
    }

    /**
     * With no transaction open on a MySQL or MariaDB storage connection, the
     * next one it begins is set to READ COMMITTED, on the connection the
     * storage setting names.
     *
     * @param  string  $driver
     * @return void
     */
    #[DataProvider('provideEnginesSetBeforeBeginning')]
    public function testTheListenersNextTransactionOnMysqlReadsCommittedRows(string $driver): void
    {
        $connection = \Mockery::mock(Connection::class);

        $connection->allows('getDriverName')->andReturn($driver);
        $connection->allows('transactionLevel')->andReturn(0);
        $connection->expects('statement')->once()->with('set transaction isolation level read committed')->andReturnTrue();

        self::reads($connection, 'storage')->beforeBeginning();
    }

    /**
     * The outermost transaction on a PostgreSQL storage connection, once begun,
     * is set to READ COMMITTED, on the connection the storage setting names.
     *
     * @return void
     */
    public function testTheListenersOwnTransactionOnPostgresReadsCommittedRows(): void
    {
        $connection = \Mockery::mock(Connection::class);

        $connection->allows('getDriverName')->andReturn('pgsql');
        $connection->allows('transactionLevel')->andReturn(1);
        $connection->expects('statement')->once()->with('set transaction isolation level read committed')->andReturnTrue();

        self::reads($connection, 'storage')->onceBegun();
    }

    /**
     * Rows of `[driver, transaction level]`: nothing set before a transaction
     * begins.
     *
     * @return iterable<string, array{0: string, 1: int}>
     */
    public static function provideUnsetBeforeBeginning(): iterable
    {
        yield 'a caller\'s transaction on MySQL' => ['mysql', 1];

        yield 'a caller\'s transaction on MariaDB' => ['mariadb', 2];

        yield 'PostgreSQL' => ['pgsql', 0];

        yield 'SQLite' => ['sqlite', 0];
    }

    /**
     * Inside a caller's transaction on MySQL or MariaDB, which refuse a level
     * there and whose next transaction would be another, and on any other
     * engine, nothing is set before the listener's transaction begins.
     *
     * @param  string  $driver
     * @param  int  $level
     * @return void
     */
    #[DataProvider('provideUnsetBeforeBeginning')]
    public function testNothingElseIsSetBeforeBeginning(string $driver, int $level): void
    {
        $connection = \Mockery::mock(Connection::class);

        $connection->allows('getDriverName')->andReturn($driver);
        $connection->allows('transactionLevel')->andReturn($level);
        $connection->expects('statement')->never();

        self::reads($connection, 'storage')->beforeBeginning();
    }

    /**
     * Rows of `[driver, transaction level]`: nothing set once a transaction has
     * begun.
     *
     * @return iterable<string, array{0: string, 1: int}>
     */
    public static function provideUnsetOnceBegun(): iterable
    {
        yield 'a caller\'s transaction on PostgreSQL' => ['pgsql', 2];

        yield 'no transaction on PostgreSQL' => ['pgsql', 0];

        yield 'MySQL' => ['mysql', 1];

        yield 'MariaDB' => ['mariadb', 1];

        yield 'SQLite' => ['sqlite', 1];
    }

    /**
     * A transaction the listener runs inside, or one on another engine than
     * PostgreSQL, is left as it is once begun: MySQL and MariaDB have taken
     * their level before it began.
     *
     * @param  string  $driver
     * @param  int  $level
     * @return void
     */
    #[DataProvider('provideUnsetOnceBegun')]
    public function testNothingElseIsSetOnceBegun(string $driver, int $level): void
    {
        $connection = \Mockery::mock(Connection::class);

        $connection->allows('getDriverName')->andReturn($driver);
        $connection->allows('transactionLevel')->andReturn($level);
        $connection->expects('statement')->never();

        self::reads($connection, 'storage')->onceBegun();
    }

    /**
     * The committed reads over a database whose storage connection, named as
     * given, is the connection given.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $name
     * @return \SineMacula\Laravel\Iam\Provisioning\CommittedReads
     */
    private static function reads(Connection $connection, string $name): CommittedReads
    {
        $database = \Mockery::mock(DatabaseManager::class);

        $database->allows('connection')->with($name)->andReturn($connection);

        return new CommittedReads($database, new StorageConnection(new Repository(['iam' => ['storage' => ['connection' => $name]]])));
    }
}
