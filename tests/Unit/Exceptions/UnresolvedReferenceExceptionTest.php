<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;

/**
 * Unit tests for refusing a tenant, identity, principal or session an adapter
 * needs and cannot resolve (IAM-8.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(UnresolvedReferenceException::class)]
final class UnresolvedReferenceExceptionTest extends TestCase
{
    /**
     * The exception for an application that is no session guard names it, and
     * says what each MFA application must be.
     *
     * @return void
     */
    public function testItNamesAnApplicationThatIsNoSessionGuard(): void
    {
        $exception = UnresolvedReferenceException::forGuard('web');

        self::assertSame(
            'The application [web] is not a laravel-authentication guard that holds sessions, so no session of it can be resolved:'
            . ' each MFA application that verifies further factors is a guard of the jwt driver, named the same.',
            $exception->getMessage(),
        );
        self::assertSame(ReferenceKind::GUARD, $exception->kind);
        self::assertSame('web', $exception->application);
    }

    /**
     * The exception for a guard holding no session of the identity names the
     * guard and says the change is refused.
     *
     * @return void
     */
    public function testItNamesAGuardHoldingNoSessionOfTheIdentity(): void
    {
        $exception = UnresolvedReferenceException::forSession('api');

        self::assertSame(
            'The guard [api] holds no current session of the identity asked about, so the sign-in MFA names cannot be resolved;'
            . ' the change is refused rather than made against no session.',
            $exception->getMessage(),
        );
        self::assertSame(ReferenceKind::SESSION, $exception->kind);
        self::assertSame('api', $exception->application);
    }

    /**
     * The exception for a sign-in that is no session of the identity's on the
     * guard names the guard, as a reference of the kind `session`.
     *
     * @return void
     */
    public function testItNamesASignInThatIsNoSessionOfTheIdentity(): void
    {
        $exception = UnresolvedReferenceException::forSignIn('api');

        self::assertSame(
            'The sign-in MFA names is no session of the identity asked about on the guard [api], so it cannot be resolved;'
            . ' the change is refused rather than made against another session or none.',
            $exception->getMessage(),
        );
        self::assertSame(ReferenceKind::SESSION, $exception->kind);
        self::assertSame('api', $exception->application);
    }

    /**
     * The exception for an identity names its type and what it must be, on no
     * application.
     *
     * @return void
     */
    public function testItNamesAnIdentityThatCannotBeResolved(): void
    {
        $exception = UnresolvedReferenceException::forIdentity('App\Models\Robot');

        self::assertSame(
            'The identity of type [App\Models\Robot] cannot be resolved: it must implement laravel-authentication\'s Identity contract,'
            . ' and its key must be a non-empty string or an integer.',
            $exception->getMessage(),
        );
        self::assertSame(ReferenceKind::IDENTITY, $exception->kind);
        self::assertNull($exception->application);
    }

    /**
     * The exception for an identity MFA holds no factors for names its type and
     * MFA's contract it must implement, on no application.
     *
     * @return void
     */
    public function testItNamesAnIdentityMfaCannotHoldFactorsFor(): void
    {
        $exception = UnresolvedReferenceException::forMfaIdentity('App\Models\Robot');

        self::assertSame(
            'The identity of type [App\Models\Robot] cannot be resolved for MFA: it must implement laravel-mfa\'s MultiFactorAuthenticatable contract,'
            . ' which the HasFactors trait provides, so MFA can hold its factors.',
            $exception->getMessage(),
        );
        self::assertSame(ReferenceKind::IDENTITY, $exception->kind);
        self::assertNull($exception->application);
    }

    /**
     * It is a runtime exception, so every member that refuses with one (MFA's
     * session revoker and session transition among them) takes it.
     *
     * @return void
     */
    public function testItIsARuntimeException(): void
    {
        self::assertInstanceOf(\RuntimeException::class, UnresolvedReferenceException::forSession('api'));
    }
}
