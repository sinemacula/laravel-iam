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
 * `laravel-authentication`'s tenant authentication policy, answered from SSO's
 * enforcement, SSO's exemption gate and the application's MFA tenant
 * requirement (IAM-4.5).
 *
 * The rule's connections are required unless the identity is exempt, and the
 * MFA tenant requirement is the further factor; the version is a digest of all
 * three (`TenantPolicyVersion`). The gate is asked only for a session the rule
 * would refuse, with the client of the redemption admitted for that very
 * sign-in, or one of which nothing is known.
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

        /** Resolves SSO's enforcement, its exemption gate and the request's records on each call. */
        private Container $container,

        /** Asks the application's MFA tenant requirement. */
        private TenantMfaRequirements $requirements,

        /** Names the identity to SSO. */
        private IdentityReferences $identities,
    ) {}

    /**
     * What the tenant requires of the session, or of the sign-in about to write
     * one.
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
     * The exemption gate's answer for a session the rule would refuse, or
     * `null` when it need not be asked.
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

        return $this->container->make(ExemptionGate::class)->admit($policy, $context->application, $identity, $client, $sessionId);
    }

    /**
     * The tenant's identifier as a string, as SSO and MFA name it.
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
     * The id of the session judged, or `null` for a sign-in whose session is
     * not written yet.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @return ?string
     */
    private static function sessionIdOf(?Session $session): ?string
    {
        return $session === null ? null : IdentifierCoercion::stringify($session->getSessionIdentifier());
    }
}
