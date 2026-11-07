<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Contracts\TenantMfaRequirement;
use SineMacula\Laravel\Iam\Exceptions\TenantMfaRequirementMisconfiguredException;

/**
 * Unit tests for the exception a tenant MFA requirement that cannot be built
 * throws (IAM-4.5): each names the key or the binding at fault and the
 * contract, never a tenant or an identity, and is a logic exception.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TenantMfaRequirementMisconfiguredException::class)]
final class TenantMfaRequirementMisconfiguredExceptionTest extends TestCase
{
    /**
     * A class named that is no requirement names the key, the class and the
     * contract.
     *
     * @return void
     */
    public function testAClassNamedThatIsNoRequirementNamesTheKey(): void
    {
        $exception = TenantMfaRequirementMisconfiguredException::forClass('iam.tenancy.mfa_requirement', 'App\Tenancy\Missing', TenantMfaRequirement::class);

        self::assertInstanceOf(\LogicException::class, $exception);
        self::assertSame(
            'iam.tenancy.mfa_requirement names [App\Tenancy\Missing], which is not a class implementing ' . TenantMfaRequirement::class
            . ', so no tenant\'s MFA requirement can be answered.',
            $exception->getMessage(),
        );
    }

    /**
     * A value that is no class name names the key, the value's type and the
     * contract, never the value.
     *
     * @return void
     */
    public function testAValueThatIsNoClassNameNamesTheKeyAndTheType(): void
    {
        $exception = TenantMfaRequirementMisconfiguredException::forValue('iam.tenancy.mfa_requirement', 'array', TenantMfaRequirement::class);

        self::assertInstanceOf(\LogicException::class, $exception);
        self::assertSame(
            'iam.tenancy.mfa_requirement holds a value of type [array], which names no class implementing ' . TenantMfaRequirement::class
            . ', so no tenant\'s MFA requirement can be answered: name the class, or leave it null to require nothing.',
            $exception->getMessage(),
        );
    }

    /**
     * A binding that resolves to no requirement names the binding, what it
     * resolved to and the contract.
     *
     * @return void
     */
    public function testABindingThatResolvesToNoRequirementNamesTheBinding(): void
    {
        $exception = TenantMfaRequirementMisconfiguredException::forBinding(TenantMfaRequirement::class, \stdClass::class, TenantMfaRequirement::class);

        self::assertSame(
            'The container binding of ' . TenantMfaRequirement::class . ' resolves to [stdClass], which is no tenant MFA requirement,'
            . ' so no tenant\'s MFA requirement can be answered: bind it to a class implementing ' . TenantMfaRequirement::class . '.',
            $exception->getMessage(),
        );
    }
}
