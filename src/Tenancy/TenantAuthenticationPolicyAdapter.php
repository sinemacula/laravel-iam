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
 * enforcement, SSO's exemption gate and the application's tenant MFA
 * requirement together (IAM-4.5, AUTH-2.12, SSO-4.1).
 *
 * For a session acting in a tenant, or a sign-in about to write one, it asks,
 * in this order and on every call, caching nothing:
 *
 * 1. SSO's `Enforcement::policy()` for the tenant and the application (the
 *    guard), which reads the enforcing tenant's stored rule on the write
 *    connection, or reads nothing while SSO's `enforcement` feature is off;
 * 2. where the rule is required and the session was not established through one
 *    of its satisfying connections, SSO's `ExemptionGate::admit()`, the only
 *    place SSO's exemption contract is asked, which reports `ExemptionUsed` for
 *    an exemption it grants once the transaction commits. The application's
 *    `EnforcementExemption` is its own data, which neither SSO nor this package
 *    watches: whenever its answer changes for an identity (a grant or a
 *    withdrawal), the application reports the change for every tenant whose
 *    enforcement the identity was, or is now, exempted from, with
 *    `Iam::tenantPolicies()->changed($tenant)` inside the transaction that
 *    publishes it, which judges the tenant's sessions there and once more after
 *    that transaction commits, the strict cut-off `laravel-authentication` asks
 *    for, so its sessions are judged again at
 *    once, the outcome being part of the version;
 * 3. the application's tenant MFA requirement (`TenantMfaRequirements`), on the
 *    write connection, for exactly the tenant asked: no inheritance down a
 *    tenant tree is applied here.
 *
 * The answer requires the rule's satisfying connections unless the rule
 * requires none or the identity is exempt, the application's requirement as its
 * further factor, and carries a version that changes whenever any of the three
 * does (`TenantPolicyVersion`). `laravel-authentication` judges the session
 * against it and refuses one through another connection as `sso_required`, with
 * no pending continuation.
 *
 * The connection a session, or a sign-in, was established through is the one
 * the context names (`connectionId()`), asked only once the rule requires a
 * connection, so a tenant with nothing enforced costs no read of the session's
 * provenance. `laravel-authentication` finds it once for the policy and its own
 * judgement alike: the sign-in's own, in memory, before its session is written,
 * and otherwise the one the session's recorded provenance names, pending
 * sessions included, read current where it holds the session's row locked (a
 * refresh, a switch, an external re-authentication, `tenantPolicyChanged()`),
 * so a session committed after the transaction's snapshot is never taken for
 * one through no connection. It is asked while the policy answers, never after.
 * So the gate is asked only for a session the rule would refuse, and an exempt
 * identity's sessions through a satisfying connection report no exemption.
 *
 * It only reads, and takes no lock of its own: the current read of the
 * provenance is `laravel-authentication`'s, and SSO's `policy()` reads without
 * locking. Inside a transaction that has already read on MySQL at REPEATABLE
 * READ, the rule is read as of that transaction's snapshot. A redemption's
 * sign-in is judged by SSO against the rule it locked, as it is now, and
 * recorded on the provenance at that rule's version; were the rule changed
 * between the redemption's first read and SSO's lock, this answer would be the
 * older rule's, so it could only refuse what SSO admitted (`sso_required`,
 * rolled back, the code left unspent for another attempt) or record a version
 * the next judgement of the session does not skip, never admit what SSO
 * refused.
 *
 * `laravel-authentication` hands the policy no client. The gate is handed the
 * client of the redemption admitted in this request when that redemption is the
 * very sign-in, or the very session's re-authentication, being judged: the one
 * it links the identity of and names the session of, none for a sign-in
 * (`AdmittedRedemptions::clientFor()`), the client SSO was handed for its
 * admission. Any other judgement (a refresh, a switch, `tenantPolicyChanged()`,
 * a sign-in this package did not redeem) hands it a client of which nothing is
 * known, as a job's is: an `ExemptionUsed` it reports then carries no IP
 * address or user agent. Nothing reads the request. The identity is named to
 * SSO through the morph map (`IdentityReferences`), and a tenant whose
 * identifier is no string or integer throws `UnresolvedReferenceException`
 * inside the caller's transaction (IAM-8.2). An exception from SSO, the gate or
 * the application's requirement propagates. Stateless (IAM-8.1): SSO's
 * enforcement, the gate and the request's records are resolved from the
 * container on every call.
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

        /** Asks the application's tenant MFA requirement. */
        private TenantMfaRequirements $requirements,

        /** Names the identity to SSO. */
        private IdentityReferences $identities,
    ) {}

    /**
     * What the tenant requires of the session, or of the sign-in about to write
     * one: the connections SSO's enforcement requires unless the identity is
     * exempt, the application's further factor, and the version of the whole.
     *
     * @param  \SineMacula\Laravel\Authentication\Tenancy\TenantPolicyContext  $context
     * @return \SineMacula\Laravel\Authentication\Tenancy\TenantRequirement
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \JsonException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Iam\Exceptions\TenantMfaRequirementMisconfiguredException
     */
    #[\Override]
    public function requirementFor(TenantPolicyContext $context): TenantRequirement
    {
        $policy    = $this->container->make(Enforcement::class)->policy(self::tenantIdOf($context->tenant), $context->application);
        $exemption = $this->exemption($policy, $context);
        $rule      = $this->requirements->ruleFor($context->tenant, $context->application);
        $enforced  = $policy->isRequired() && $exemption !== ExemptionOutcome::EXEMPT;

        return new TenantRequirement(TenantPolicyVersion::of($policy, $exemption, $rule), $rule->requirement, $enforced ? $policy->connectionIds : null);
    }

    /**
     * The exemption gate's answer for a session, or a sign-in, the rule would
     * refuse, or `null` when the gate need not be asked: the rule requires no
     * connection, or the session was established through one that satisfies it.
     * The gate is handed the client of the redemption admitted for that very
     * sign-in or re-authentication, or a client of which nothing is known.
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
     * The id SSO names the tenant by: its identifier as a string, as
     * `laravel-authentication` matches a session's tenant.
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
     * The id of the session judged, as SSO reports it with an exemption, or
     * `null` for a sign-in whose session is not written yet.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @return ?string
     */
    private static function sessionIdOf(?Session $session): ?string
    {
        return $session === null ? null : IdentifierCoercion::stringify($session->getSessionIdentifier());
    }
}
