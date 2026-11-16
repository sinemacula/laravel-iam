<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy;

use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyContext;
use SineMacula\Laravel\Authentication\Tenancy\TenantRequirement;

/**
 * Answers `laravel-authentication`'s tenant policy from the application's MFA
 * tenant requirement alone, while SSO's adapters are off.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TenantFactorPolicyAdapter implements TenantAuthenticationPolicy
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Tenancy\TenantMfaRequirements  $requirements
     */
    public function __construct(

        /** Asks the application's MFA tenant requirement. */
        private TenantMfaRequirements $requirements,
    ) {}

    /**
     * The further factor the tenant requires of the session or sign-in.
     *
     * @param  \SineMacula\Laravel\Authentication\Tenancy\TenantPolicyContext  $context
     * @return \SineMacula\Laravel\Authentication\Tenancy\TenantRequirement
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \JsonException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    #[\Override]
    public function requirementFor(TenantPolicyContext $context): TenantRequirement
    {
        $factor = $this->requirements->requirementFor($context, TenantAuthenticationPolicyAdapter::tenantIdOf($context->tenant));

        return new TenantRequirement(TenantPolicyVersion::ofFactor($factor), $factor);
    }
}
