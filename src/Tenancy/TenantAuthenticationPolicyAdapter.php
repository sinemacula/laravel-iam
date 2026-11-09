<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\ConnectionResolverInterface;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Database\StorageConnection;
use SineMacula\Laravel\Authentication\Proofs\SessionProofs;
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
 * The connection a session was established through is the one its recorded
 * provenance names, read on the write connection. Inside a transaction on
 * `laravel-authentication`'s storage connection, where it asks the policy under
 * the session's row lock (a refresh, a switch, an external re-authentication,
 * `tenantPolicyChanged()`), it is read current, as `laravel-authentication`
 * reads it there (`SessionProofs::connectionId($session, true)`): on MySQL at
 * REPEATABLE READ a plain read answers from the transaction's snapshot, which
 * may be older than the session its locking read found, so a session committed
 * after that snapshot would be taken for one through no connection. Outside one
 * it is read plainly, and nothing acts on the answer atomically. The public
 * reader of a session's proofs (`Auth::sessions($guard)->firstFactor()`) cannot
 * stand in for it: it answers nothing for a pending session, which the policy
 * is asked about too, so a pending SSO session would be taken for one through
 * no connection. A sign-in, whose session is not written yet, is established
 * through the connection of the redemption SSO admitted in this request for the
 * identity (`AdmittedRedemptions`), which SSO judged against the rule under its
 * own locks; any other sign-in through no connection. Only this package's SSO
 * capability records that redemption, so the adapter is bound only while it is
 * on (`TenancySeams`). So the gate is asked only for a session the rule would
 * refuse, and an exempt identity's sessions through a satisfying connection
 * report no exemption.
 *
 * It only reads. The current read of the provenance takes a shared lock of the
 * session's provenance row on MySQL and MariaDB (`SessionProofs`), held until
 * the transaction ends, which comes after the session's row in
 * `laravel-authentication`'s order (the session's row, then its proofs), so it
 * inverts nothing; it takes no other lock, and SSO's `policy()` reads without
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
 * container on every call, and the storage connection's transaction level is
 * read on every call.
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
     * @param  \Illuminate\Database\ConnectionResolverInterface  $database
     */
    public function __construct(

        /** Resolves SSO's enforcement, its exemption gate and the request's records on each call. */
        private Container $container,

        /** Asks the application's tenant MFA requirement. */
        private TenantMfaRequirements $requirements,

        /** Names the identity to SSO. */
        private IdentityReferences $identities,

        /** Resolves `laravel-authentication`'s storage connection, to learn whether a transaction is open on it. */
        private ConnectionResolverInterface $database,
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
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private function exemption(EnforcementPolicy $policy, TenantPolicyContext $context): ?ExemptionOutcome
    {
        if (!$policy->isRequired()) {
            return null;
        }

        $identity     = $this->identities->reference($context->identity);
        $admitted     = $this->container->make(AdmittedRedemptions::class);
        $sessionId    = self::sessionIdOf($context->session);
        $connectionId = $context->session === null
            ? $admitted->connectionFor($identity)
            : SessionProofs::connectionId($context->session, $this->isInTransaction());

        if ($connectionId !== null && $policy->isSatisfiedBy($connectionId)) {
            return null;
        }

        $client = $admitted->clientFor($identity, $sessionId) ?? new SsoClient(null, null);

        return $this->container->make(ExemptionGate::class)->admit($policy, $context->application, $identity, $client, $sessionId);
    }

    /**
     * Whether a transaction is open on `laravel-authentication`'s storage
     * connection, where its sessions and their provenance live, so the
     * session's provenance is read current, as the class describes.
     *
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    private function isInTransaction(): bool
    {
        return $this->database->connection(StorageConnection::name())->transactionLevel() > 0;
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
