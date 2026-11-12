<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Exceptions\UnlinkedSignInException;

/**
 * Unit tests for refusing an admitted sign-in that is linked to no identity.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(UnlinkedSignInException::class)]
final class UnlinkedSignInExceptionTest extends TestCase
{
    /**
     * The message names the application and the connection.
     *
     * @return void
     */
    public function testItNamesTheApplicationAndTheConnection(): void
    {
        $exception = UnlinkedSignInException::forConnection('api', 'connection-1');

        self::assertSame(
            'SSO admitted a sign-in for the application [api] through the connection [connection-1] that is linked to no identity:'
            . ' the redemption is rolled back, since only a linked result signs anyone in.',
            $exception->getMessage(),
        );
        self::assertSame('api', $exception->application);
        self::assertSame('connection-1', $exception->connectionId);
        self::assertInstanceOf(\RuntimeException::class, $exception);
    }
}
