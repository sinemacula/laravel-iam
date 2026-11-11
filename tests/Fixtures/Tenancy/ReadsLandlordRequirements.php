<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Tenancy;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\TenantRequirement;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * MFA's tenant requirement read through a landlord model, refusing a tenant the
 * connection does not hold.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ReadsLandlordRequirements implements TenantRequirement
{
    /**
     * Multifactor authentication for a tenant the connection holds, as it reads
     * it.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $tenant
     * @return \SineMacula\Laravel\Mfa\Requirements\Requirement
     *
     * @throws \RuntimeException
     */
    #[\Override]
    public function requirementFor(MultiFactorAuthenticatable $identity, string $application, string $tenant): Requirement
    {
        if (LandlordTenant::query()->find($tenant) === null) {
            throw new \RuntimeException('The landlord holds no such tenant.');
        }

        return Requirement::none()->withMultifactor();
    }
}
