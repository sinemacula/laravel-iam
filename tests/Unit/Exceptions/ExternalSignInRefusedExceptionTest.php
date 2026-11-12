<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Iam\Exceptions\ExternalSignInRefusedException;

/**
 * Unit tests for the refused external sign-in exception.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExternalSignInRefusedException::class)]
final class ExternalSignInRefusedExceptionTest extends TestCase
{
    /**
     * The message names the reason and the result is carried as given.
     *
     * @return void
     */
    public function testItCarriesTheFailedResult(): void
    {
        $result    = SignInResult::failed(FailureReason::LINK_MISMATCH);
        $exception = ExternalSignInRefusedException::for($result);

        self::assertSame(
            'laravel-authentication refused the external sign-in [link_mismatch]: the redemption is rolled back, and the handoff code stays unspent.',
            $exception->getMessage(),
        );
        self::assertSame($result, $exception->result);
        self::assertInstanceOf(\RuntimeException::class, $exception);
    }
}
