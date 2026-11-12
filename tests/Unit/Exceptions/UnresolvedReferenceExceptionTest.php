<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;

/**
 * Unit tests for the unresolved reference exception.
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
     * An application that is no session guard is named as a guard reference.
     *
     * @return void
     */
    public function testItNamesAnApplicationThatIsNoSessionGuard(): void
    {
        $exception = UnresolvedReferenceException::forGuard('web');

        self::assertSame(
            'The application [web] is not a laravel-authentication guard that holds sessions, so no session of it can be resolved:'
            . ' each application MFA verifies further factors for, or SSO signs people in to, is a guard of the jwt driver, named the same.',
            $exception->getMessage(),
        );
        self::assertSame(ReferenceKind::GUARD, $exception->kind);
        self::assertSame('web', $exception->application);
    }

    /**
     * A guard holding no session of the identity is named.
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
     * A sign-in that is no session of the identity names the guard.
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
     * An unresolved identity names its type, on no application.
     *
     * @return void
     */
    public function testItNamesAnIdentityThatCannotBeResolved(): void
    {
        $exception = UnresolvedReferenceException::forIdentity('App\Models\Robot');

        self::assertSame(
            'The identity of type [App\Models\Robot] cannot be resolved: it must implement laravel-authentication\'s Identity contract.',
            $exception->getMessage(),
        );
        self::assertSame(ReferenceKind::IDENTITY, $exception->kind);
        self::assertNull($exception->application);
    }

    /**
     * An identity MFA cannot hold factors for names its type and the contract.
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
     * An unresolved SSO identity reference names its type, never its id.
     *
     * @return void
     */
    public function testItNamesAnIdentityReferenceThatCannotBeResolved(): void
    {
        $exception = UnresolvedReferenceException::forIdentityReference('person');

        self::assertSame(
            'The identity SSO names, of type [person], cannot be resolved: its type must name, through the morph map, an Eloquent model'
            . ' implementing laravel-authentication\'s Identity contract, whose morph class it is, and its id the key of one stored.',
            $exception->getMessage(),
        );
        self::assertSame(ReferenceKind::IDENTITY, $exception->kind);
        self::assertNull($exception->application);
    }

    /**
     * An unresolved tenant names its id.
     *
     * @return void
     */
    public function testItNamesATenantThatCannotBeResolved(): void
    {
        $exception = UnresolvedReferenceException::forTenant('tenant-1');

        self::assertSame(
            'The tenant [tenant-1] cannot be resolved: laravel-authentication\'s tenant resolver must resolve it to the tenant whose identifier it is,'
            . ' so the sessions acting in it can be judged; the change is refused rather than left unenforced.',
            $exception->getMessage(),
        );
        self::assertSame(ReferenceKind::TENANT, $exception->kind);
        self::assertNull($exception->application);
    }

    /**
     * An unresolved grant tenant names its id and the unreported widening.
     *
     * @return void
     */
    public function testItNamesAGrantsTenantThatCannotBeResolved(): void
    {
        $exception = UnresolvedReferenceException::forGrantTenant('tenant-9');

        self::assertSame(
            'The tenant [tenant-9] a grant holds in cannot be resolved: laravel-authentication\'s tenant resolver must resolve it to the tenant of its type'
            . ' whose identifier it is, so the widening of the identity\'s scope can be reported to laravel-sso; the grant is refused rather than written unreported.',
            $exception->getMessage(),
        );
        self::assertSame(ReferenceKind::TENANT, $exception->kind);
        self::assertNull($exception->application);
    }

    /**
     * A tenant with an unusable identifier names neither tenant nor identifier.
     *
     * @return void
     */
    public function testItNamesATenantWhoseIdentifierCannotNameIt(): void
    {
        $exception = UnresolvedReferenceException::forTenantIdentifier();

        self::assertSame(
            'The tenant cannot be named by its identifier: a tenant\'s identifier must be a non-empty string or an integer,'
            . ' so its authentication policy can be asked; the session is refused rather than judged against no policy.',
            $exception->getMessage(),
        );
        self::assertSame(ReferenceKind::TENANT, $exception->kind);
        self::assertNull($exception->application);
    }

    /**
     * It is a runtime exception, which every refusing member takes.
     *
     * @return void
     */
    public function testItIsARuntimeException(): void
    {
        self::assertInstanceOf(\RuntimeException::class, UnresolvedReferenceException::forSession('api'));
    }
}
