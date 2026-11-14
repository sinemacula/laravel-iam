# Audit Mapping

## Purpose

How the members' events are recorded in `laravel-audit-log`: the mappers, codes and definitions this package registers,
the reader that gives audit-log a guard's caller, the capture exclusions that stop double records, and audit-log's
access policy answered from `laravel-authorization`'s grants. Audit-log owns storage, integrity and retention; this
package only describes. The storage connection is in `storage-and-transactions.md`.

## Registration

- `Audit\AuditRegistrations::register()` runs from `IamServiceProvider::boot()`. Audit-log binds its registries in
  `register()` and freezes them once every provider has booted, so registering in `boot()` works in any provider order.
- If audit-log's provider has not registered yet, registration waits for the application's `booted()` callback, which
  still runs before the freeze. An audit-log that never registers refuses the boot (`MemberNotRegisteredException`),
  except while a configuration command such as `config:clear` or `package:discover` runs.
- A first registration after boot throws `\LogicException`, since audit-log would take none and nothing would be
  recorded. A repeat is a no-op (`AuditRegistrations::REGISTERED`).
- While `iam.audit.mappers` is on, each member's marker interface (`AuthenticationEvent`, `MfaEvent`, `SsoEvent`,
  `AuthorizationEvent`) maps to one mapper, and every case of the five code enums is defined. The switch is off only
  for an explicit `false`, `0`, `off` or `no`, since a trail skipped by a typo is lost for good.

## Codes

- A code names what happened, never the event's class. Audit-log's own code is reused where the meaning is the same:
  `authentication.signed_in`, `sign_in_failed`, `locked_out`, `signed_out`, `account.email_verified` and
  `account.password_reset`. Everything else has a code under its member's prefix: `authentication.*`, `session.*`,
  `mfa.*`, `sso.*` and `authorization.*`, defined in `Audit\Enums`.
- `AuthenticationFailed` is recorded by its flow: a sign-in's as `sign_in_failed`, as `locked_out` when the
  identifier, session or IP has used up its attempts (`rate_limited`), and as `sign_in_failed_concealed` when its
  reason is concealed. Audit-log's codes drop the `concealed` flag, so an account's own limit is never `locked_out`.
  Other flows are `authentication.{flow}_failed` or `session.{flow}_failed`. SSO's refusals are one code,
  `sso.flow_failed`, keeping the flow.
- Every definition is version 1 and drops every property it does not list (`Contracts\ListsProperties`). SSO's
  administration and every `laravel-authorization` change are `access_management`, so they can be kept longer.
- No code keeps a secret or free text. A factor is kept by id and type, reasons are codes, an identifier change's
  identifiers are pseudonymised, a refused sign-in's identifier is hashed by audit-log (`withIdentifier()`), and an
  MFA reset's free-text reason, a policy document and SSO's provisioning grant are never kept.
- Six `authorization.*` codes the requirements do not list (role exclusions, expiry changes, resource policies and
  `system_override_used`) are kept because each is a privilege change.

## Mapping

- A mapper reads only the event, its context and the morph map, never the request, `Auth::user()` or a guard. It
  returns the builder, or `null` to skip.
- `AuthenticationFailed` and a recorded `DecisionEvaluated` are written with `afterTransaction()`. Callers roll back
  after a refusal on purpose (SSO redemptions, MFA's step-up and pending completion), and a refusal is still a fact.
  Every other record is written at once.
- Skipped: a bind's `PrincipalAssigned` and `SessionAuthenticated`, a refresh's `SignedIn`, which repeats
  `Refreshed`, and every allowed decision but a preview, a break-glass one or one `laravel-authorization` reports as a
  sensitive action (`DecisionReport::SENSITIVE_ACTION`). Pairs that are two facts, such as
  `SessionCreated` and `SignedIn`, or SSO's and `laravel-authentication`'s halves of one external sign-in, are
  recorded once each.
- The actor follows `Mappers\Enums\Attribution`:
  - `SUBJECT`: the identity acted for itself, such as a sign-in or its own session change.
  - `NOBODY`: every refusal, since its author was never proven, and what a member did by itself, such as an expiry, a
    detected replay or a lockout.
  - `CALLER`: left to the contributors where the member does not say who acted, such as a revocation, an API key
    managed or an SSO administration call with no acting identity.
  - An operator the event names (MFA's `Actor`, SSO's acting identity) is the actor whatever the attribution says.
- An actor from the event brings its principal and tenant, explicitly none when the event names none. A record left to
  the caller keeps the principal the event acted on as properties (`session_principal_*`, `scope_principal_*`,
  `key_principal_*`), since the record's principal is the caller's. Its tenant stays the event's.
- The record's credential is the one the activity used. A credential being managed (a passkey added or removed, an API
  key issued, revoked or rotated) is a property (`passkey_id`, `key_id`), so a leaked key's trail is not mixed with its
  management.
- The guard, session and client come from the event when it names them; MFA's and SSO's application is the guard.
- `Audit\References` reads every member's type through the morph map. A tenant is its identifier under the one type
  `tenant`. A reference audit-log cannot hold fails the capture (`AuditCaptureFailed`) rather than be recorded wrong.
- `Audit\Correlation` gives the first id that applies: `sso:{connection}:{request}` for one SSO sign-in,
  `mfa:{challenge}` or `authentication:{challenge}` for a challenge, `authorization:{operation}` for one management
  call, else `session:{id}`. An id audit-log would refuse becomes `null`, so the record is still written.
- A `laravel-authorization` tenant is recorded by identifier only once its key resolves back to the same tenant
  (`TenantTranslator::idOf()`). Otherwise the record has no tenant, since the key could be another tenant's
  identifier, and a record with no tenant is shown to no tenant-scoped viewer.
- A deletion that removed grants covers every grantee beyond its subject through `PendingRecord::covering()`.
- A denial for `insufficient_authentication` is a plain `access_denied`; the event does not say if a step-up follows.

## The caller's context

- `Audit\AuthenticationActorReader` is audit-log's `HeldActorReader`. Audit-log's guard walk asks it about a guard it
  cannot read through `GuardHelpers`.
- It reads only what an `AbstractGuard` has already bound (identity, principal, tenant, session) and returns `null`
  for any other guard or none bound. It never authenticates. A tenant the guard cannot load is left out.
- Audit-log fills the record from it and carries the caller into queued jobs.

## No double records

- A `jwt` guard dispatches Laravel's `Login`, `Failed` and `Logout` beside the mapped events, so every `jwt` and
  `api_key` guard must be in `audit-log.capture.laravel.except_guards`. Audit-log's Gate capture stays off, since
  `laravel-authorization` answers the Gate and its decisions are mapped.
- `Audit\CaptureExclusions` only computes these for `iam:check` and never writes configuration. A malformed
  `except_guards` is refused, naming the key and never the value. `AuditSettings::refusesUnregisteredCodes()` reads
  audit-log's `definitions.require_registered` the same way.

## Access and administration

- `Authorization\AuditAccessPolicyAdapter` answers audit-log's `AuditAccessPolicy` over `DenyAllPolicy` while
  `iam.adapters.authorization` is on. It decides the viewer's own tenant, its memberships and each tenant a grant
  route starts in, and returns `tenants()` narrowed to the categories every tenant allows, else `onlyAbout()` the
  viewer in its `.own` tenants, else `none()`. A permission that needs an authentication requirement never counts,
  since the policy is not told the reader's session.
- `Authorization\PermissionCatalogue` declares `audit-log.{purpose}`, `.{category}` and `.own`, and SSO's and MFA's
  administrative operations, reusing SSO's own names. `Authorization\AdministrativeCheck::authorize()` checks one for a
  resolved `Subject` in the scope that subject names.
- Nothing in this package reads the trail. Audit-log refuses a read inside `Iam::transaction()` only while it stores on
  the storage connection. `iam:check` notes a different audit-log connection.

## Member gaps

- `laravel-authentication`: the `jwt` guard's `attempt()` and `login()` dispatch only Laravel's `Login`, so those
  sign-ins go unrecorded once the guard is excluded; an `AuthenticationEvent` for them would close it.
- `laravel-authentication`: the `api_key` guard's `logout()` and trusted `login()` have the same gap.
- `laravel-authentication`: `ContextualGuard` has no bound-only caller snapshot, so the reader needs `AbstractGuard`.
- `laravel-audit-log`: `RecordPipeline` calls `Str::uuid7($occurredAt)`, which rewinds the shared UUIDv7 state; the
  test suite resets it in `Tests\TestCase::setUp()`.
- `laravel-audit-log`: `Contribution` has no credential filler, so only the mappers set the credential.
- `laravel-mfa`: `EnrollmentAbandoned` names no cause or operator, so its actor is left to the caller.
- `laravel-mfa`, `laravel-sso`: event contexts give a tenant id with no type, so tenants share the one type `tenant`.
- `laravel-authorization`: `usedBreakGlass` is always false until BL-70, so `break_glass_used` is never recorded yet.
