<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Exceptions\StorageConnectionMismatchException;

/**
 * Unit tests for refusing a member storage connection that differs from the
 * shared one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(StorageConnectionMismatchException::class)]
final class StorageConnectionMismatchExceptionTest extends TestCase
{
    /**
     * The exception for a key names the key and both connections, and says how
     * to resolve the mismatch.
     *
     * @return void
     */
    public function testItNamesTheKeyAndBothConnections(): void
    {
        $exception = StorageConnectionMismatchException::forKey('mfa.storage.connection', 'mysql', 'pgsql');

        self::assertSame(
            'mfa.storage.connection names [mysql], but iam.storage.connection names [pgsql]: every member keeps its tables on the one storage connection,'
            . ' so a change that spans members runs in one transaction. Unset the member key, or set it to the same connection.',
            $exception->getMessage(),
        );
        self::assertSame('mfa.storage.connection', $exception->key);
        self::assertSame('mysql', $exception->member);
        self::assertSame('pgsql', $exception->storage);
    }

    /**
     * The default connection, which `null` stands for, is named as `[default]`
     * on either side, and kept as `null` on the exception.
     *
     * @return void
     */
    public function testTheDefaultConnectionIsNamedAsDefault(): void
    {
        $member  = StorageConnectionMismatchException::forKey('sso.storage.connection', null, 'pgsql');
        $storage = StorageConnectionMismatchException::forKey('authentication.storage.connection', 'mysql', null);

        self::assertStringStartsWith('sso.storage.connection names [default], but iam.storage.connection names [pgsql]:', $member->getMessage());
        self::assertNull($member->member);
        self::assertStringStartsWith('authentication.storage.connection names [mysql], but iam.storage.connection names [default]:', $storage->getMessage());
        self::assertNull($storage->storage);
    }

    /**
     * Built directly, the exception carries the given message, no code and no
     * previous exception.
     *
     * @return void
     */
    public function testItCarriesTheGivenMessage(): void
    {
        $exception = new StorageConnectionMismatchException('Mismatch.', 'sso.storage.connection', 'a', 'b');

        self::assertSame('Mismatch.', $exception->getMessage());
        self::assertSame(0, $exception->getCode());
        self::assertNull($exception->getPrevious());
    }
}
