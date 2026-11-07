<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Contracts;

use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Iam\Tenancy\TenantMfaRule;

/**
 * Tenant MFA requirement contract: the application's one answer for which
 * tenants require which further factors of a session acting in them (IAM-4.5).
 *
 * Which tenants require MFA is the application's own data. The application
 * implements this once, names it in `iam.tenancy.mfa_requirement` (or binds it
 * in the container), and the package routes the same answer to MFA's tenant
 * requirement and into `laravel-authentication`'s tenant authentication policy,
 * so the two members never disagree about a tenant.
 *
 * It answers for exactly the tenant asked: the package applies no inheritance
 * down a tenant tree, so an application whose tenants inherit a requirement
 * works that out here. It is asked on the write connection (inside
 * `laravel-authentication`'s `WriteConnection::during()` for the tenant), at
 * sign-in, at a choice of principal, at activation, on every refresh and
 * switch, and while MFA works out a session's requirement, sometimes while
 * `laravel-authentication` holds the session's row lock: read the application's
 * own state from the write connection every time, cache nothing, take no lock
 * and write nothing.
 *
 * The rule's version must change whenever the answer does, so a session
 * recorded at the version is not judged again for nothing, and stay the same
 * while it does not; a rule that cannot be versioned answers a `null` version,
 * which is never taken as already checked. When the answer changes, report the
 * change so sessions that no longer meet it end: call
 * `Iam::tenantPolicies()->changed($tenant)` inside the transaction that
 * publishes it, on the storage connection (`Iam::transaction()` opens one).
 * That judges the tenant's sessions there, so the two commit or roll back
 * together, and once more after that transaction commits, the strict cut-off
 * `laravel-authentication`'s `tenantPolicyChanged()` asks for: a session that
 * entered the tenant while the first pass ran, having read the old answer, is
 * not among the sessions the first pass judged, and only the second judges it.
 * Calling `Auth::sessions()->tenantPolicyChanged($tenant)` directly, make the
 * same two calls, the first inside that transaction and the second after it
 * commits. The same report is due, for every tenant concerned, whenever the
 * application's SSO `EnforcementExemption` grants or withdraws an identity's
 * exemption, since the tenant's policy answers from both. A tenant it cannot
 * answer for throws: it never answers that nothing is required because it could
 * not tell.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface TenantMfaRequirement
{
    /**
     * What the tenant requires of a session acting in it on the application,
     * and the version of that answer; it throws when it cannot answer for the
     * tenant.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  string  $application
     * @return \SineMacula\Laravel\Iam\Tenancy\TenantMfaRule
     *
     * @throws \Throwable
     */
    public function requirementFor(Tenant $tenant, string $application): TenantMfaRule;
}
