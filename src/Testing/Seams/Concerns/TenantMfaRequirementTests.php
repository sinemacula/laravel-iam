<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Testing\Seams\Concerns;

use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Iam\Contracts\TenantMfaRequirement;
use SineMacula\Laravel\Iam\Testing\Seams\TenantMfaRequirementContract;

/**
 * The `TenantMfaRequirement` contract kit (IAM-4.5): the requirement answers a
 * tenant the same way while nothing changes, versions a changed answer anew,
 * and throws for a tenant it cannot answer for.
 *
 * A test case proves the application's requirement by using this trait and
 * implementing the hooks against its own data: a tenant it answers for, a way
 * to change what that tenant requires (as an administrator would), and a tenant
 * it cannot answer for (one whose settings cannot be read, say). Each check
 * delegates to `TenantMfaRequirementContract`.
 *
 * @phpstan-require-extends \PHPUnit\Framework\TestCase
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
trait TenantMfaRequirementTests
{
    /**
     * The same tenant is answered the same way, at the same version, while
     * nothing changes.
     *
     * @return void
     */
    public function testTenantMfaRequirementIsDeterministic(): void
    {
        $requirement = $this->tenantMfaRequirement();
        $tenant      = $this->tenantMfaTenant();
        $application = $this->tenantMfaApplication();

        TenantMfaRequirementContract::assertDeterministic(static fn () => $requirement->requirementFor($tenant, $application));
    }

    /**
     * A changed answer comes at another version, or at none.
     *
     * @return void
     */
    public function testTenantMfaRequirementVersionChangesWithTheAnswer(): void
    {
        $requirement = $this->tenantMfaRequirement();
        $tenant      = $this->tenantMfaTenant();
        $application = $this->tenantMfaApplication();

        TenantMfaRequirementContract::assertVersionChangesWithTheAnswer(
            static fn () => $requirement->requirementFor($tenant, $application),
            fn () => $this->changeTenantMfaRequirement($tenant),
        );
    }

    /**
     * A tenant the requirement cannot answer for throws, rather than be
     * answered as requiring nothing.
     *
     * @return void
     */
    public function testTenantMfaRequirementThrowsRatherThanAnswersNothing(): void
    {
        $requirement = $this->tenantMfaRequirement();
        $tenant      = $this->unanswerableTenant();
        $application = $this->tenantMfaApplication();

        TenantMfaRequirementContract::assertThrowsRatherThanAnswersNothing(static fn () => $requirement->requirementFor($tenant, $application));
    }

    /**
     * The requirement under test.
     *
     * @return \SineMacula\Laravel\Iam\Contracts\TenantMfaRequirement
     */
    abstract protected function tenantMfaRequirement(): TenantMfaRequirement;

    /**
     * A tenant the requirement answers for.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\Tenant
     */
    abstract protected function tenantMfaTenant(): Tenant;

    /**
     * The application asked about.
     *
     * @return string
     */
    abstract protected function tenantMfaApplication(): string;

    /**
     * Change what the tenant requires, as the application would.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return void
     */
    abstract protected function changeTenantMfaRequirement(Tenant $tenant): void;

    /**
     * A tenant the requirement cannot answer for.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\Tenant
     */
    abstract protected function unanswerableTenant(): Tenant;
}
