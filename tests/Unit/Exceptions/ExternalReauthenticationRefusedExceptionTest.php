<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Sessions\AccessTokenResult;
use SineMacula\Laravel\Iam\Exceptions\ExternalReauthenticationRefusedException;

/**
 * Unit tests for the refused external re-authentication exception.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExternalReauthenticationRefusedException::class)]
final class ExternalReauthenticationRefusedExceptionTest extends TestCase
{
    /**
     * The message names the reason and the result is carried as given.
     *
     * @return void
     */
    public function testItCarriesTheFailedResult(): void
    {
        $result    = AccessTokenResult::failed(FailureReason::SSO_REQUIRED);
        $exception = ExternalReauthenticationRefusedException::for($result);

        self::assertSame(
            'laravel-authentication refused the external re-authentication [sso_required]: the redemption is rolled back, and the handoff code stays unspent.',
            $exception->getMessage(),
        );
        self::assertSame($result, $exception->result);
        self::assertInstanceOf(\RuntimeException::class, $exception);
    }
}
