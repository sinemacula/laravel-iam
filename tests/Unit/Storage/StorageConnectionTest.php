<?php

declare(strict_types = 1);

namespace Tests\Unit\Storage;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Storage\StorageConnection;

/**
 * Unit tests for reading the one storage connection every member keeps its
 * tables on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(StorageConnection::class)]
final class StorageConnectionTest extends TestCase
{
    /**
     * The shared connection is read from `iam.storage.connection`, and the
     * members whose keys must name it are authentication, MFA and SSO.
     *
     * @return void
     */
    public function testTheKeysAreTheSharedKeyAndTheMembers(): void
    {
        self::assertSame('iam.storage.connection', StorageConnection::KEY);
        self::assertSame(['authentication.storage.connection', 'mfa.storage.connection', 'sso.storage.connection', 'authorization.connection'], StorageConnection::MEMBER_KEYS);
    }

    /**
     * A configured name is the shared connection.
     *
     * @return void
     */
    public function testAConfiguredNameIsTheConnection(): void
    {
        $connection = new StorageConnection(new Repository(['iam' => ['storage' => ['connection' => 'pgsql']]]));

        self::assertSame('pgsql', $connection->name());
    }

    /**
     * An unset key means the default connection.
     *
     * @return void
     */
    public function testAnUnsetKeyIsTheDefaultConnection(): void
    {
        $connection = new StorageConnection(new Repository);

        self::assertNull($connection->name());
    }

    /**
     * An empty name means the default connection, as an unset key does.
     *
     * @return void
     */
    public function testAnEmptyNameIsTheDefaultConnection(): void
    {
        $connection = new StorageConnection(new Repository(['iam' => ['storage' => ['connection' => '']]]));

        self::assertNull($connection->name());
    }

    /**
     * The key is read on every call, so a change to the configuration is seen
     * at once.
     *
     * @return void
     */
    public function testTheKeyIsReadOnEveryCall(): void
    {
        $config     = new Repository;
        $connection = new StorageConnection($config);

        $config->set(StorageConnection::KEY, 'mysql');

        self::assertSame('mysql', $connection->name());

        $config->set(StorageConnection::KEY, 'pgsql');

        self::assertSame('pgsql', $connection->name());
    }

    /**
     * Rows of `[value]`: a key value that is neither a name, `null` nor empty.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideMalformedConnections(): iterable
    {
        yield 'integer' => [1];
        yield 'false' => [false];
        yield 'array' => [['mysql']];
    }

    /**
     * A value that is neither a name, `null` nor empty fails closed, naming the
     * key, rather than falling back to the default connection.
     *
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideMalformedConnections')]
    public function testAMalformedValueFailsClosed(mixed $value): void
    {
        $connection = new StorageConnection(new Repository(['iam' => ['storage' => ['connection' => $value]]]));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`iam.storage.connection` must be a connection name, or null or empty for the default connection.');

        $connection->name();
    }

    /**
     * Any connection key is read the same way: a name as given, an unset or
     * empty one as the default connection.
     *
     * @return void
     */
    public function testAnyConnectionKeyIsReadTheSameWay(): void
    {
        $config = new Repository(['mfa' => ['storage' => ['connection' => 'mysql']], 'sso' => ['storage' => ['connection' => '']]]);

        self::assertSame('mysql', StorageConnection::read($config, 'mfa.storage.connection'));
        self::assertNull(StorageConnection::read($config, 'sso.storage.connection'));
        self::assertNull(StorageConnection::read($config, 'authentication.storage.connection'));
    }

    /**
     * A malformed member key fails closed, naming that key.
     *
     * @return void
     */
    public function testAMalformedMemberKeyFailsClosedNamingIt(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`sso.storage.connection` must be a connection name, or null or empty for the default connection.');

        StorageConnection::read(new Repository(['sso' => ['storage' => ['connection' => 5]]]), 'sso.storage.connection');
    }
}
