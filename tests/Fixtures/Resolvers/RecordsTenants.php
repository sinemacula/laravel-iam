<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Resolvers;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\TenantRequirement;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * A tenant requirement that asks an additional verification of every tenant,
 * and records each tenant MFA asks it about, in the order asked.
 *
 * It stands in for an application's tenant requirement, so the active tenant
 * adapter's tests can show which tenant MFA composes a requirement with.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordsTenants implements TenantRequirement
{
    /** @var int The age, in seconds, of the additional verification every tenant asks for. */
    public const int MAX_AGE = 600;

    /** @var list<string> The tenants asked about, in the order asked. */
    public array $tenants = [];

    /**
     * The tenant's requirement: an additional verification.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $tenant
     * @return \SineMacula\Laravel\Mfa\Requirements\Requirement
     */
    #[\Override]
    public function requirementFor(MultiFactorAuthenticatable $identity, string $application, string $tenant): Requirement
    {
        $this->tenants[] = $tenant;

        return Requirement::none()->withAdditionalVerification(self::MAX_AGE);
    }
}
