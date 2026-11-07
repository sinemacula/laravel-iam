<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Tenancy;

use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Iam\Contracts\TenantMfaRequirement;
use SineMacula\Laravel\Iam\Tenancy\TenantMfaRule;

/**
 * A tenant MFA requirement written to this package's contract: a plain model
 * read of the landlord's tenant, which pins nothing itself and relies on being
 * asked on the write connection, as the contract promises. A tenant the
 * connection holds requires multifactor authentication; one it does not hold
 * cannot be answered for, and throws.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ReadsLandlordRequirements implements TenantMfaRequirement
{
    /**
     * Multifactor authentication for a tenant the connection holds, as it reads
     * it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  string  $application
     * @return \SineMacula\Laravel\Iam\Tenancy\TenantMfaRule
     *
     * @throws \RuntimeException
     */
    #[\Override]
    public function requirementFor(Tenant $tenant, string $application): TenantMfaRule
    {
        $stored = LandlordTenant::query()->find($tenant->getTenantIdentifier());

        if ($stored === null) {
            throw new \RuntimeException('The landlord holds no such tenant.');
        }

        return new TenantMfaRule(new Requirement(multifactor: new RequirementPart), 'landlord-1');
    }
}
