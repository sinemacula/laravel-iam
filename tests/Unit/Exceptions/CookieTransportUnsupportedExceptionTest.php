<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Exceptions\CookieTransportUnsupportedException;

/**
 * Unit tests for the exception an application is refused with when this
 * package's pending completion is bound beside a guard whose refresh token
 * travels in a cookie.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CookieTransportUnsupportedException::class)]
final class CookieTransportUnsupportedExceptionTest extends TestCase
{
    /**
     * The exception for the pending completion names the guard, why no pending
     * sign-in on it can be completed, and what the application can do.
     *
     * @return void
     */
    public function testItNamesTheGuardAndWhatToDo(): void
    {
        $exception = CookieTransportUnsupportedException::forPendingCompletion('spa');

        self::assertSame(
            'The guard [spa] carries its refresh token in a cookie, so no pending sign-in on it can be completed through MFA:'
            . ' MFA hands the pending completion no client, and laravel-authentication refuses a cookie application\'s pending session'
            . ' for a client that carries no same-site facts as [cross_site_request]. Carry the guard\'s refresh token in the body,'
            . ' bind your own SineMacula\Laravel\Mfa\Contracts\PendingCompletion, or turn iam.adapters.mfa off.',
            $exception->getMessage(),
        );
        self::assertSame('spa', $exception->guard);
    }

    /**
     * Built directly, the exception carries the given message, no code and no
     * previous exception.
     *
     * @return void
     */
    public function testItCarriesTheGivenMessage(): void
    {
        $exception = new CookieTransportUnsupportedException('Unsupported.', 'spa');

        self::assertSame('Unsupported.', $exception->getMessage());
        self::assertSame(0, $exception->getCode());
        self::assertNull($exception->getPrevious());
    }
}
