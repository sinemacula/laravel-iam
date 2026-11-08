<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Exceptions\PublicationFailedException;

/**
 * Unit tests for the exception `iam:install` stops with when a file cannot be
 * copied to where its provider publishes it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PublicationFailedException::class)]
final class PublicationFailedExceptionTest extends TestCase
{
    /**
     * The exception names the path and says how to resolve it, and is a runtime
     * failure.
     *
     * @return void
     */
    public function testItNamesThePathAndSaysHowToResolveIt(): void
    {
        $exception = PublicationFailedException::forFile('/app/config/mfa.php');

        self::assertSame('/app/config/mfa.php could not be published; make its directory writable and run iam:install again.', $exception->getMessage());
        self::assertInstanceOf(\RuntimeException::class, $exception);
        self::assertNull($exception->getPrevious());
    }

    /**
     * The error that stopped the copy is kept as the previous exception.
     *
     * @return void
     */
    public function testItKeepsTheErrorThatStoppedTheCopy(): void
    {
        $error     = new \ErrorException('copy(/app/config/mfa.php): Failed to open stream: Permission denied');
        $exception = PublicationFailedException::forFile('/app/config/mfa.php', $error);

        self::assertSame($error, $exception->getPrevious());
        self::assertSame(0, $exception->getCode());
    }
}
