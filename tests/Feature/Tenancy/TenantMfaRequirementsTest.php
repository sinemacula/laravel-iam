<?php

declare(strict_types = 1);

namespace Tests\Feature\Tenancy;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyContext;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\Translation\RequirementTranslator;
use SineMacula\Laravel\Iam\Tenancy\TenantMfaRequirements;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Requirements\Requirement as MfaRequirement;
use Tests\Fixtures\Resolvers\ClaimedTenant;
use Tests\Fixtures\Tenancy\ScriptedTenantRequirement;
use Tests\TestCase;

/**
 * Feature tests for asking the application's binding of MFA's tenant
 * requirement.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TenantMfaRequirements::class)]
final class TenantMfaRequirementsTest extends TestCase
{
    /**
     * MFA's default is no requirement; any other binding is one.
     *
     * @return void
     */
    public function testARequirementIsConfiguredOnceBoundOffMfasDefault(): void
    {
        self::assertFalse($this->requirements()->isConfigured());

        ScriptedTenantRequirement::bind($this->app);

        self::assertTrue($this->requirements()->isConfigured());
    }

    /**
     * The binding is asked for the identity, the application and the tenant id,
     * and its answer translated.
     *
     * @return void
     */
    public function testTheBindingIsAskedAndItsAnswerTranslated(): void
    {
        $scripted = ScriptedTenantRequirement::bind($this->app)->require('tenant-1', MfaRequirement::none()->withMultifactor(300));

        $requirement = $this->requirements()->requirementFor(self::context(\Mockery::mock(Identity::class, MultiFactorAuthenticatable::class)), 'tenant-1');

        self::assertEquals(new Requirement(multifactor: new RequirementPart(300)), $requirement);
        self::assertSame([['tenant' => 'tenant-1', 'application' => 'api']], $scripted->asked());
    }

    /**
     * With MFA's default, nothing is required and the identity is not asked
     * about.
     *
     * @return void
     */
    public function testWithMfasDefaultNothingIsRequired(): void
    {
        self::assertTrue($this->requirements()->requirementFor(self::context(\Mockery::mock(Identity::class)), 'tenant-1')->isEmpty());
    }

    /**
     * Once a requirement is bound, an identity MFA holds no factors for is
     * refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityMfaHoldsNoFactorsForIsRefused(): void
    {
        $scripted = ScriptedTenantRequirement::bind($this->app);

        try {
            $this->requirements()->requirementFor(self::context(\Mockery::mock(Identity::class)), 'tenant-1');

            self::fail('The requirement answered.');
        } catch (UnresolvedReferenceException $exception) {
            self::assertSame(ReferenceKind::IDENTITY, $exception->kind);
        }

        self::assertSame([], $scripted->asked());
    }

    /**
     * The requirements over the application's container.
     *
     * @return \SineMacula\Laravel\Iam\Tenancy\TenantMfaRequirements
     */
    private function requirements(): TenantMfaRequirements
    {
        return new TenantMfaRequirements($this->app ?? self::fail('The application has not booted.'), new RequirementTranslator);
    }

    /**
     * The context of the identity acting in `tenant-1` on `api`.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return \SineMacula\Laravel\Authentication\Tenancy\TenantPolicyContext
     */
    private static function context(Identity $identity): TenantPolicyContext
    {
        return new TenantPolicyContext('api', $identity, \Mockery::mock(Principal::class), new ClaimedTenant('tenant-1'), null, static fn (): ?string => null);
    }
}
