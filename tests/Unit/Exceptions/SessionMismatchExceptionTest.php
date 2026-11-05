<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Exceptions\SessionMismatchException;

/**
 * Unit tests for refusing a sign-in that is not the guard's current session.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionMismatchException::class)]
final class SessionMismatchExceptionTest extends TestCase
{
    /**
     * The exception names the guard and says the change is refused, naming
     * neither session.
     *
     * @return void
     */
    public function testItNamesTheGuard(): void
    {
        $exception = SessionMismatchException::forGuard('api');

        self::assertSame(
            'The sign-in MFA names is not the current session of the guard [api]: the change is refused rather than judged against another session.',
            $exception->getMessage(),
        );
        self::assertSame('api', $exception->application);
        self::assertInstanceOf(\RuntimeException::class, $exception);
    }
}
