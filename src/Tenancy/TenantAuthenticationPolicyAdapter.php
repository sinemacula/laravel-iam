<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyContext;
use SineMacula\Laravel\Authentication\Tenancy\TenantRequirement;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Sso\AdmittedRedemptions;
use SineMacula\Laravel\Iam\Sso\IdentityReferences;
use SineMacula\Laravel\Sso\Contracts\Enforcement;
use SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy;
use SineMacula\Laravel\Sso\Enforcement\Enums\ExemptionOutcome;
use SineMacula\Laravel\Sso\Enforcement\ExemptionGate;
use SineMacula\Laravel\Sso\Http\ClientContext as SsoClient;

/**
 * Answers `laravel-authentication`'s tenant policy from SSO's enforcement and
 * exemption gate and the application's MFA tenant requirement.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TenantAuthenticationPolicyAdapter implements TenantAuthenticationPolicy
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Iam\Tenancy\TenantMfaRequirements  $requirements
     * @param  \SineMacula\Laravel\Iam\Sso\IdentityReferences  $identities
     */
    public function __construct(

        /** Resolves SSO's enforcement, its exemption gate and contract, and the request's records on each call. */
        private Container $container,

        /** Asks the application's MFA tenant requirement. */
        private TenantMfaRequirements $requirements,

        /** Names the identity to SSO. */
        private IdentityReferences $identities,
    ) {}

    /**
     * What the tenant requires of the session or sign-in.
     *
     * @param  \SineMacula\Laravel\Authentication\Tenancy\TenantPolicyContext  $context
     * @return \SineMacula\Laravel\Authentication\Tenancy\TenantRequirement
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \JsonException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    #[\Override]
    public function requirementFor(TenantPolicyContext $context): TenantRequirement
    {
        $tenantId  = self::tenantIdOf($context->tenant);
        $policy    = $this->container->make(Enforcement::class)->policy($tenantId, $context->application);
        $exemption = $this->exemption($policy, $context);
        $factor    = $this->requirements->requirementFor($context, $tenantId);
        $enforced  = $policy->isRequired() && $exemption !== ExemptionOutcome::EXEMPT;

        return new TenantRequirement(TenantPolicyVersion::of($policy, $exemption, $factor), $factor, $enforced ? $policy->connectionIds : null);
    }

    /**
     * Whether the identity is exempt, or `null` when the rule would not refuse.
     *
     * @param  \SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy  $policy
     * @param  \SineMacula\Laravel\Authentication\Tenancy\TenantPolicyContext  $context
     * @return ?\SineMacula\Laravel\Sso\Enforcement\Enums\ExemptionOutcome
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private function exemption(EnforcementPolicy $policy, TenantPolicyContext $context): ?ExemptionOutcome
    {
        if (!$policy->isRequired()) {
            return null;
        }

        $connectionId = $context->connectionId();

        if ($connectionId !== null && $policy->isSatisfiedBy($connectionId)) {
            return null;
        }

        $identity  = $this->identities->reference($context->identity);
        $sessionId = self::sessionIdOf($context->session);
        $client    = $this->container->make(AdmittedRedemptions::class)->clientFor($identity, $sessionId) ?? new SsoClient(null, null);

        $gate = $this->container->make(ExemptionGate::class);

        // Only an admitted call reports its exemption.
        return $context->rejudging
            ? $gate->judge($policy, $context->application, $identity)
            : $gate->admit($policy, $context->application, $identity, $client, $sessionId);
    }

    /**
     * The tenant's identifier as SSO and MFA name it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return string
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private static function tenantIdOf(Tenant $tenant): string
    {
        $tenantId = IdentifierCoercion::stringify($tenant->getTenantIdentifier());

        return $tenantId === null || $tenantId === '' ? throw UnresolvedReferenceException::forTenantIdentifier() : $tenantId;
    }

    /**
     * The session's id, or `null` for a sign-in not yet written.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @return ?string
     */
    private static function sessionIdOf(?Session $session): ?string
    {
        return $session === null ? null : IdentifierCoercion::stringify($session->getSessionIdentifier());
    }
}
