# Tenant Authentication Policy

## Purpose

The package answers `laravel-authentication`'s `TenantAuthenticationPolicy` from SSO's enforcement, SSO's exemption
gate and the application's implementation of laravel-mfa's `TenantRequirement`, and versions the answer so a change to
any of them reaches existing sessions. The redemptions are in `sso-redemption-and-revocation.md` and the subtree
judging in `provisioning-and-tenancy.md`.

## Seam

| Member seam                       | Adapter                                     | Default replaced          | Lifetime  |
| --------------------------------- | ------------------------------------------- | ------------------------- | --------- |
| AUTH `TenantAuthenticationPolicy` | `Tenancy\TenantAuthenticationPolicyAdapter` | `RequireNothingOfTenants` | transient |

The row is in `Tenancy\TenancySeams` and bound while `iam.adapters.sso` is on, whatever `iam.adapters.mfa` says. It
is mandatory while `sso.features.enforcement` is on or MFA's tenant requirement is bound off its default. With the SSO
adapters off the application binds the policy itself.

## Decisions

- The answer is composed on every call, with nothing cached:
  1. SSO's `Enforcement::policy()` for the tenant and the guard as the application;
  2. SSO's `ExemptionGate::admit()`, only where the rule requires a connection and the session or sign-in was not made
     through one that satisfies it;
  3. MFA's tenant requirement for the identity, the application and the tenant, translated part by part.

  The connections are the rule's satisfying ones, or `null` when the rule requires none or the identity is exempt.
- The tenant requirement is the same binding MFA asks itself (`TenantMfaRequirements`), so the two members never
  disagree. While it is MFA's `NoTenantRequirement` nothing is asked. Once one is bound, an identity that is not
  `MultiFactorAuthenticatable` throws rather than answer nothing.
- The requirement answers for exactly the tenant asked; the package applies no inheritance of it down the tree.
- The version (`TenantPolicyVersion::of()`) is the SHA-256 of SSO's serialised policy, the gate's outcome and the
  requirement, so it changes whenever anything the answer depends on does.
- The session's connection is asked of `TenantPolicyContext::connectionId()` only once the rule requires one, so a
  tenant with nothing enforced costs no read of the session's provenance.
- The gate is handed the client of the redemption this package admitted in the request (`AdmittedRedemptions`), so
  `ExemptionUsed` carries that request's IP address and user agent. Every other judgement (a refresh, a switch, a
  password or passkey sign-in, `tenantPolicyChanged()`) hands it an empty client.
- `Iam::tenantPolicies()->changed($tenant)` is the application's report of a changed requirement or exemption, made
  inside the transaction that publishes it. It calls `laravel-authentication`'s `tenantPolicyChanged()`, which judges
  the tenant's sessions there and again once the transaction commits, catching a session that entered the tenant
  meanwhile.
- Neither SSO nor this package watches the application's exemptions or requirements, so a change left unreported
  leaves the tenant's sessions acting until their next refresh.

## Invariants

- The policy only reads and takes no lock of its own; the current read of a session's provenance is
  `laravel-authentication`'s, inside its own lock order.
- No request is read; the identity is named to SSO through the morph map.
- A tenant whose identifier is neither a non-empty string nor an integer throws `UnresolvedReferenceException` inside
  the caller's transaction.
- Turning a rule off revokes nothing: SSO calls no revocation then, and the policy requires no connection.
- A requirement that cannot answer throws, and the sign-in, refresh or change fails rather than require nothing.

## Member gaps

- `laravel-authentication`'s `TenantPolicyContext` carries no `ClientContext`, so the gate is handed the admitted
  redemption's client where there is one and an empty client otherwise.
