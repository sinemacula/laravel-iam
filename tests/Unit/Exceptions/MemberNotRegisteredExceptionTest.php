<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Exceptions\MemberNotRegisteredException;
use SineMacula\Laravel\Sso\SsoServiceProvider;

/**
 * Unit tests for the exception a member that had not registered by the end of
 * the application's boot is refused with.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MemberNotRegisteredException::class)]
final class MemberNotRegisteredExceptionTest extends TestCase
{
    /**
     * The exception for a member's storage names the member's provider and its
     * key, and says how to resolve it.
     *
     * @return void
     */
    public function testItNamesTheProviderAndTheKey(): void
    {
        $exception = MemberNotRegisteredException::forStorage('sso.storage.connection', SsoServiceProvider::class);

        self::assertSame(
            SsoServiceProvider::class . ' had not registered when the application finished booting, so sso.storage.connection could not be put on'
            . ' iam.storage.connection: every member keeps its tables on the one storage connection, so a change that spans members runs in one'
            . ' transaction. Register every member\'s service provider before the application finishes booting.',
            $exception->getMessage(),
        );
        self::assertSame('sso.storage.connection', $exception->key);
        self::assertSame(SsoServiceProvider::class, $exception->provider);
    }

    /**
     * Built directly, the exception carries the given message, no code and no
     * previous exception.
     *
     * @return void
     */
    public function testItCarriesTheGivenMessage(): void
    {
        $exception = new MemberNotRegisteredException('Missing.', 'sso.storage.connection', SsoServiceProvider::class);

        self::assertSame('Missing.', $exception->getMessage());
        self::assertSame(0, $exception->getCode());
        self::assertNull($exception->getPrevious());
    }
}
