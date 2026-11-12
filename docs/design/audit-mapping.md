# Audit Mapping

## Purpose

This note describes how the package records `laravel-authentication`'s, MFA's, SSO's and `laravel-authorization`'s
events in `laravel-audit-log` (section 9 of the requirements), and what surrounds that mapping: the registrations made
while the application boots, the reader that hands audit-log the caller a `laravel-authentication` guard holds
(IAM-9.7), the exclusions from audit-log's own capture that keep a suite event from being recorded twice
(IAM-9.6), the operational events offered to the application's alerting (IAM-9.8), the refusal of a trail read inside a
change that spans members (IAM-9.9), audit-log's access policy answered from `laravel-authorization`'s grants
(IAM-6.10) with the catalogue of the members' administrative permissions it reads (IAM-6.9), and the gaps in the
members the mapping works around. Audit-log decides storage, integrity and retention; this package
only describes. The storage connection and the cross-member transaction are in `storage-and-transactions.md`, and the
worker reset that forgets a guard's caller between jobs in `long-running-processes.md`.

## Invariants

### Registration

- `Audit\AuditRegistrations::register()` runs from `IamServiceProvider::boot()`. Audit-log binds its registries as
  shared instances in its `register()` and freezes them from a `booted()` callback its own `boot()` queues, which runs
  only once every provider has booted, so once audit-log's provider has registered, the registrations are made at
  once, in every provider order, this package's boot before audit-log's included.
- When audit-log's provider has not registered yet (an application provider registers it from its own `boot()`, or it
  is left out of discovery), nothing is resolved from it, since a recorder resolved then would be a throwaway with
  registries of its own: the registrations are queued for when the application has booted. That callback is queued
  before audit-log's freeze, which audit-log queues only as it boots, later, so it runs while audit-log still takes
  registrations. An audit-log still unregistered then refuses the boot (`MemberNotRegisteredException::forAuditTrail()`,
  naming `AuditLogServiceProvider`), as a member this package aligns does, except while one of the console commands
  that list, describe, discover, cache or clear configuration runs (`config:clear`, `optimize:clear`,
  `package:discover` and the others the provider names): the provider hands `register()` its verdict, nothing is
  registered then, and the command runs, so a stale package manifest or a provider left out of discovery can still be
  inspected and cleared, as the storage check allows for the other members.
- A provider booted again once the application has booted finds its part registered (`AuditRegistrations::REGISTERED`)
  and registers nothing more; a provider whose first registration comes only then is refused (`\LogicException`),
  failing its boot, rather than leave an application that seems to record the members' events and records none.
- While `iam.audit.mappers` is on (read leniently by `Audit\AuditSettings`: only `false`, `0`, `off` or `no` turns it
  off), it maps each member's marker interface to one mapper (`AuditRegistrations::MAPPERS`): `AuthenticationEvent` to
  `Audit\Mappers\AuthenticationEventMapper`, `MfaEvent` to `MfaEventMapper`, `SsoEvent` to `SsoEventMapper`. No
  member event implements two of them, and audit-log never maps its own events (`AuditLogEvent`), so every member
  event has exactly one mapper and none of audit-log's has any. MFA's legacy events no longer exist, so nothing is
  excepted.
- In the same call it defines every case of this package's code enums (`AuditRegistrations::CODES`):
  `Audit\Enums\AuthenticationActivity`, `SessionActivity`, `MfaActivity` and `SsoActivity`. None of their codes is one
  of audit-log's (`CapturedActivity`), so no code is defined twice; audit-log's own are reused unchanged and never
  defined here. A registration repeated identically changes nothing. With the switch off nothing is mapped or defined.

### Codes and definitions (IAM-9.2, IAM-9.3)

- A mapper names each record's code by what happened, never by the event's class. Audit-log's own code is reused for a
  suite event that means the same, with its definition unchanged, so one query answers across guards: a sign-in
  (`SignedIn`) is `authentication.signed_in`, a refused sign-in `authentication.sign_in_failed`, a sign-in refused
  because the identifier, the session or the IP address has used up its attempts (`rate_limited`)
  `authentication.locked_out`, denied with its reason, explicitly by no one and about no one, with the identifier
  hashed, as audit-log records Laravel's `Lockout`, a user's own sign-out (`SessionRevoked` for `signed_out`)
  `authentication.signed_out`, an email address verified (`IdentifierVerified` for `email`) `account.email_verified`,
  and a password reset (`PasswordSet` for `reset`) `account.password_reset`. A record under one of these carries no
  property, since its definition keeps none of the suite's; its columns (actor, subject, principal, tenant, guard,
  session, client, correlation, reason) say the rest.
- A suite event that needs other properties has a code of its own under its member's reserved prefix: `authentication.*`
  and `session.*` for `laravel-authentication`, `mfa.*` and `sso.*`. A sign-in refused for a concealed reason is
  `authentication.sign_in_failed_concealed`, since audit-log's `sign_in_failed` drops the `concealed` flag a read needs
  to hide the reason; the account's own limit (`account_rate_limited`) is concealed, and so is recorded there and never
  as `authentication.locked_out`, whose definition would drop the flag too. Every other revocation is `session.revoked`,
  and an identity's sessions ended together `session.signed_out_everywhere`, each keeping its revocation reason as a
  property, since a success carries no outcome reason.
- A refusal (`AuthenticationFailed`) is recorded by its flow (`AuthenticationFlow`), never all as a refused sign-in:
  `sign_in` as above, `bearer` as `authentication.request_rejected`, `api_key` as `authentication.api_key_rejected`,
  `client_credentials`, `code_request`, `identifier_verification`, `password_reset`, `identifier_change`,
  `factor_code` and `password_change` as `authentication.{flow}_failed`, and `refresh`, `switch`, `sign_out`, `step_up`
  and `reauthentication` as `session.{flow}_failed`, `factor_change` as `session.factor_recheck_failed`. SSO's
  refusals are one code, `sso.flow_failed`, keeping their flow: its flows are the stages of one sign-in.
- Every definition is version 1 and drops every property it does not list. `laravel-authentication`'s, MFA's and SSO's
  flows, links, exemptions, key expiry warnings and refreshes are in the `security` category; the administration of
  SSO's connections, domains, enforcement and keys, a change to who may sign in and how, is in `access_management`, so
  it can be kept longer. Each enum lists every property its codes keep (`Contracts\ListsProperties`), and a
  mapper hands a record exactly those (`Mappers\Snapshot::describe()`), so no record carries a property only to have
  it dropped.
- What a code keeps is never a secret or free text: a factor by its id and type, never its label or destination; a
  revocation's, a refusal's and SSO's reasons as codes; an identifier change's identifiers pseudonymised (a keyed
  hash), so records of one identifier match without holding it; the identifier a refused sign-in named hashed by
  audit-log (`withIdentifier()`), never a property; an MFA reset's reason, which an operator gives in words, never;
  an unlinked SSO result's provisioning grant, never.

### Mapping (IAM-9.4, IAM-9.5)

- A mapper reads only the event it is handed, its context snapshot and its own fields, and the morph map; never the
  request, `Auth::user()`, the guard or any other current state. It sets the code explicitly, describes, and returns
  the builder, or `null` to skip; it never records, and chooses no timing but a refusal's: see the next item.
- A refusal (`AuthenticationFailed`) is written with audit-log's `afterTransaction()`: once the outermost transaction
  on audit-log's storage connection ends, committed or rolled back, and at once when none is open. Several callers roll
  back on purpose after `laravel-authentication` refuses: this package's SSO redemptions, so the code stays unspent;
  MFA's step-up, pending completion and enrolment; and any transaction the application opened. A record written inside
  that transaction would roll back with it.
- The noise of a bind (`PrincipalAssigned`, `SessionAuthenticated`) is skipped, and so is a refresh's `SignedIn`
  (`refresh` true), which repeats the `Refreshed` recorded beside it. Every other pair the members report is two facts
  and is recorded once each: a sign-in's `SessionCreated` and `SignedIn`; SSO's `ResultVerified` and
  `HandoffRedeemed` and `laravel-authentication`'s `ExternalResultRedeemed`; SSO's `ReauthenticationCompleted` and
  `laravel-authentication`'s `Reauthenticated`; SSO's `FlowFailed` for a redemption and `AuthenticationFailed`; SSO's
  `ResultUnlinked` and `ExternalResultUnlinked`; MFA's `VerificationPassed` and `FactorConfirmed`, and its
  `RecoveryCodeUsed` and `RecoveryCodesLow`.
- The actor follows `Mappers\Enums\Attribution`. The identity acting for itself (`SUBJECT`): a sign-in, a session's own
  changes (a return to pending its own switch or refresh made among them, as its sibling `Refreshed` is), a
  verification, an MFA action naming no operator (a lockout lifted, a factor removed, recovery codes made or removed:
  MFA documents a lift with no actor as the identity's own), a link its own flow made. Explicitly no one (`NOBODY`,
  `by(null)`), so no contributor fills the ambient caller in: every refusal, whose author was never proven, and what a
  member did by itself (a detected replay, an enrolment expired, a factor disabled or a lockout applied after failures,
  a key nearing expiry, a recheck, a lapse, a failed or JWKS refresh, a link suspended by a scope's widening, a flow
  started before anyone was known). Left to the contributors (`CALLER`): what the member does not say who did (a
  revocation, an identity's sessions ended together, a return to pending after a factor change, a passkey removed, an
  API key managed, an MFA enrolment abandoned, an SSO administration helper called with no acting identity, a link a
  connection's subject migration made among them). An operator the event names (MFA's `Actor`, SSO's acting identity) is
  the actor whatever the attribution says. MFA's `FactorEnabled`, a factor its failures disabled enabled again through
  `Mfa::enableFactor()`, always names its actor, so `mfa.factor_enabled` is that actor's, on the identity, keeping the
  factor's id and type as a lifted lockout's `mfa.lockout_lifted` does.
- MFA abandons an enrolment (`EnrollmentAbandoned`) when the identity replaces or cancels it, when an operator resets
  the identity's factors, and by itself once its confirmation attempts run out, and the event names neither its cause
  nor an operator, so the record is never the identity's: it is left to the contributors, which name the operator
  serving a reset and the person serving their own replacement or cancellation. An abandonment once the attempts run
  out is the caller's too, the person whose confirmations failed, though it is what MFA did by itself; a cause on the
  event would let it be by no one (see the gaps below). A link SSO's subject migration made (`LinkCreated` with origin
  `migration`) is an administration operation's, whose acting identity is optional, never the relinked identity's.
- With an actor from the event, the principal and tenant are the event's too, explicitly none when it names none, so a
  caller's never lands on another person's record; with the actor left to the contributors, and with an operator, the
  principal is left to them, since it is the actor's (audit-log's principal is who the actor acted as), and the tenant
  is the event's when it names one, the isolation boundary the activity happened in, so a tenant's trail holds what was
  done to its principals whoever did it. The principal a `laravel-authentication` event left to the caller names is
  what the activity was done to, so it is kept as properties, its type through the morph map: a bulk sign-out's
  principal scope (`scope_principal_type`, `scope_principal_id`, none for an identity's), an API key's principal
  (`key_principal_type`, `key_principal_id`), and a revoked or returned session's (`session_principal_type`,
  `session_principal_id`); a passkey removed names none. The subject is
  the identity, SSO's connection for a connection's, a key's or a refresh's event, its domain for a domain's (by SSO's
  own model's type), and nothing for an enforcement change.
- The guard, session and client are the event's when it names them (`viaGuard()`, `inSession()`, `fromClient()`), and
  a part it names none of is left to the contributors; the IP and user agent are set together, so the event's IP never
  sits beside another request's user agent. MFA's and SSO's application stands for the guard, which is the same
  name in this package. The credential is `laravel-authentication`'s `credential_id` (`usingCredential()`) when it is
  the credential the activity used (a passkey used, an API key, bearer or client credentials refusal, a client
  credentials grant); a passkey added or removed and an API key issued, revoked or rotated name the credential they
  manage instead, which is kept as a property (`passkey_id`, `key_id`, beside a rotation's `previous_key_id`) and never
  as the record's credential.
- `Audit\References` translates every member's keys (`identity_type`, `identity_morph_class`, `principal_type`,
  `principal_morph_class`, an actor's type) through the application's morph map: a mapped class is named by its
  alias, anything else as it is. A tenant (`tenant_id`, SSO's `connection_tenant_id` when it names no active one) is
  its opaque tenant identifier under the one type `tenant`, since MFA and SSO give it no type and the identifier need
  not be any model's key. A reference audit-log cannot hold fails the capture, contained, rather than be recorded as
  another.
- `Audit\Correlation` gives one id per record, the first that applies: one SSO sign-in as
  `sso:{connection_id}:{request_reference}`, on every SSO event of the flow and on `laravel-authentication`'s redemption
  events; a challenge, `mfa:{challenge}` for MFA's code and verification events and a refused factor code (which name
  the same challenge), `authentication:{challenge}` for `laravel-authentication`'s own; else `session:{session_id}`.
  A missing part means no id, and an id over 191 bytes, or one audit-log's `correlatedWith()` would refuse, is none,
  so correlation never loses a record. Every change of one `laravel-authorization` management call is
  `authorization:{operation_id}`, its operation's id (AUTHZ-15.2); a decision carries no operation, so none.
- Decisions this note records, beyond the plan's: a sign-in refused for `rate_limited` is audit-log's own
  `authentication.locked_out` (IAM-9.2 lists it among the codes to reuse), about no one as audit-log's own capture of
  `Lockout` is, while the account's own limit stays on the concealed code; an MFA enrolment abandoned and an SSO link a
  subject migration made are the caller's, never the identity's; a record left to the caller keeps the principal the
  event names as properties while its tenant stays the event's, the boundary the activity happened in, rather than being
  left to the contributors beside the caller's principal; a credential an event manages (a passkey added or removed, an
  API key issued, revoked or rotated) is a property, never the record's `credential_id`, which audit-log defines as the
  credential used, so the trail of what a leaked key did is never mixed with its management; a `jwt` guard's `attempt()`
  and `login()` sign-ins go unrecorded on an excluded guard rather than be recorded here from Laravel's `Login`, a gap
  left to `laravel-authentication`; a job's caller frame is left once the application has booted, as audit-log's own is,
  and is frame state the explicit reset keeps; and the code enums are `Audit\Enums\AuthenticationActivity`,
  `SessionActivity`, `MfaActivity` and `SsoActivity` (`src/Audit/Enums/*.php`, tested in
  `tests/Unit/Audit/Enums/*Test.php`), not the manifest's `Audit\Codes\*` (its M7 units row and its
  `src/Audit/Codes/*.php` and `tests/Unit/Audit/Codes/*Test.php` rows), because the house coding standard, which the
  checks enforce, requires every enum to be declared in an `Enums` namespace, as `Bindings\Enums` and `Mappers\Enums`
  are; the authorization code enum follows them, as `Audit\Enums\AuthorizationActivity`, not the M11 manifest's
  `Audit\Codes\AuthorizationActivity` (and its test, `tests/Unit/Audit/Enums/AuthorizationActivityTest.php`).
- Decision this note records, beyond the plan's: every refusal is written after the transaction, not only those inside
  a transaction this package rolls back, since MFA and the application roll back around `laravel-authentication`'s
  calls too. IAM-9.5's "without dropping either" holds for a refused redemption with `laravel-authentication`'s one
  record, correlated as the SSO sign-in it ended, and for a refused step-up or pending completion with that refusal
  beside MFA's failed verification.

### The caller's context (IAM-9.7)

- `Audit\AuthenticationActorReader` is bound as audit-log's `HeldActorReader`. Audit-log's own guard walk asks it about
  the first guard holding a user, which on a `jwt` or `api_key` guard audit-log cannot read through `GuardHelpers`.
- It reads only what an `AbstractGuard` has bound (identity, principal, active tenant, session), snapshotted through
  `laravel-authentication`'s `EventContext` and referred to as the mappers refer (`Audit\References`). It returns
  `null` for any other guard or one holding no one, and leaves out a tenant the guard cannot load. It never resolves a
  request, calls `Auth::caller()` or authenticates.
- Audit-log fills the record and carries the actor, principal, tenant and session into queued jobs: an open actor gets
  all of them and the guard, the same actor set by a mapper gets the principal, tenant and session, and anyone else
  gets nothing.
- The credential IAM-9.7 lists is the mappers' alone (`usingCredential()`).

### No double records (IAM-9.6)

- `laravel-authentication`'s `jwt` guard dispatches Laravel's `Login`, `Failed` and `Logout` beside its own events,
  which the mappers record under audit-log's own codes; audit-log's listener of Laravel's events records each a second
  time unless the guard is in `audit-log.capture.laravel.except_guards`. `laravel-authorization` is always installed
  beside this package, so audit-log's Gate capture stays off: `laravel-authorization` answers the Gate, so the
  application's own Gate checks reach its decision events, which the authorization mapper records, each denial once.
- An `api_key` guard has no mapped twin to duplicate: its `logout()` dispatches Laravel's `Logout` alone (an API key has
  no session, so no `SessionRevoked` is reported beside it), and so does a trusted `login()` with `Login`. Without the
  exclusion such a sign-out is recorded once, as `authentication.signed_out`, by audit-log's own capture; with it, which
  IAM-9.6 asks for every `api_key` guard all the same, it is recorded by nothing. The gap is `laravel-authentication`'s,
  listed below.
- Not every `Login` has a mapped event beside it. A sign-in through the guard's own `attempt()`, or a trusted
  `login()`, rather than the session service, dispatches only `Login` and a bind's noise (`PrincipalAssigned`,
  `SessionAuthenticated`), never `SignedIn` or `SessionCreated`: `laravel-authentication` documents that `Login`
  reports it. On an excluded guard such a sign-in is recorded by nothing; a refused `attempt()` is still recorded once,
  from its `AuthenticationFailed`. The exclusion is kept all the same, since without it every sign-in, refusal and
  sign-out through the session service is recorded twice, and this package records no Laravel event itself: audit-log
  captures those, and a listener here deciding which `Login` has a `SignedIn` beside it would read request state the
  mappers never read. The gap is `laravel-authentication`'s, listed below.
- `Audit\CaptureExclusions` only computes, for `iam:check` to enforce (decision Q5 (a)), and
  never writes configuration: `guards()` finds every guard of the `jwt` or `api_key` driver in the order
  `auth.guards` lists them; `unexcludedGuards()` those `except_guards` lacks (none under `['*']`); `exceptGuards()` the
  value to write, what the application excludes, in its order, then every guard still missing, `['*']` kept as it is;
  `isGateCaptureOff()` only while `audit-log.capture.gate.enabled` is `false` or unset; `holds()` both. An
  `except_guards` that is no list of guard names is refused, naming the key and never the value, rather than replaced
  or read as excluding nothing. Every value is read when it is asked, never kept.
- Audit-log's `definitions.require_registered` (IAM-2.5) is read the same way and never written:
  `AuditSettings::refusesUnregisteredCodes()` says whether it is on, which it is only while it is `true`, the one value
  audit-log reads as on, for `iam:check` to enforce. With it on, a code no definition
  registers is refused rather than recorded under the permissive default; every code the mappers record is defined
  here or by audit-log, so the record sequences are pinned with it on.

### Operational alerts (IAM-9.8)

- The package registers no alert listeners. The guide lists the events an application listens to: audit-log's
  `AuditWriteFailed`, `AuditCaptureFailed` and `IntegrityCheckFailed`, and SSO's `KeyNearingExpiry`.

### Authorization (IAM-9.2, IAM-6.9, IAM-6.10)

- `Audit\Mappers\AuthorizationEventMapper` is mapped for `laravel-authorization`'s marker
  (`Contracts\AuthorizationEvent`, which `IdentityEvent` extends), so every event it dispatches is described here and
  only here. Its codes are `Audit\Enums\AuthorizationActivity` (31 codes): the decisions in `security`, every change in
  `access_management` (IAM-9.3). Audit-log's own `authorization.gate_denied` stays its own: Gate capture is off.
- Decisions. `laravel-authorization` dispatches `DecisionEvaluated` for every check, allows included (configurable
  firing is its BL-72, not built), and `AuthorizationFailed` a second time for a denial `authorize()` throws. The mapper
  records a preview (`access_previewed`: by the previewer, about the principal previewed, succeeded whatever it decided,
  its effect and reason kept as properties, never impersonation), a check a break-glass grant allowed
  (`break_glass_used`) and every other denial (`access_denied`, denied with the decision's reason code), each from
  `DecisionEvaluated` alone; `AuthorizationFailed` and every other allow are skipped, so a denial is one record. A
  record keeps the action, the resource as the check named it (`type:id`, `type:*` or a name), the application and
  the deciding statements, each by `StatementReference::toString()` (its policy's name and key, its index and sid),
  never a context value; its actor is the decision's identity, else its subject, as the subject (the principal), and
  explicitly none of either for a guest; its subject is the same person, except a preview's, which is the principal
  previewed (else its identity), since a person may hold several principals and the trail must say which was
  previewed; its tenant the decision's, and explicitly none for a platform check, so no contributor fills the
  request's in.
- A record's tenant, a decision's or a change's, is named by the tenant's identifier under `References::TENANT_TYPE`,
  as every other member's records and the audit access policy name it: `laravel-authorization` names a tenant by its
  key, so the key is taken as the identifier only once it resolves back, through `laravel-authentication`'s tenant
  resolver, to the same tenant by type and key (`TenantTranslator::idOf()`). Decision this note records: a tenant that
  does not resolve back, keyed otherwise than by its identifier or resolved by nothing, is recorded with no tenant,
  never under its key, which may be another tenant's identifier and would file the record in that tenant's trail,
  shown to that tenant's viewers and hidden from its own; an entry with no tenant is shown to no viewer scoped to
  tenants, so the trail fails closed. `iam:check` cannot test the rule, since it holds no tenant id to resolve.
- Decision this note records, beyond the plan's: a denial as `insufficient_authentication` is recorded as
  `authorization.access_denied`, denied with that reason code, as any other denial is. On the caller's own session it
  asks for a stronger proof, answered with MFA's step-up (`InsufficientAuthenticationMapping`), but a decision made on
  no session (a job's or a command's subject handed to `AdministrativeCheck`, or `Authorization::for()` given a
  principal alone) is concluded the same way by `laravel-authorization`, which asks no checker without a session, and
  nothing can step it up: it is a plain refusal, the only evidence of it. `DecisionEvaluated` does not say which of the
  two it was, so both are recorded, and the reason code tells them apart from every other denial; a step-up prompt
  therefore leaves one denial in the trail, followed by MFA's records of what the person proved.
- A decision is dispatched as it is made, inside whatever transaction is open (`laravel-authorization`'s
  `docs/design/events.md`), and a denial is a fact even when that transaction rolls back. So a decision the mapper
  records is written with `afterTransaction()`, as `laravel-authentication`'s refusals are.
- Changes. Every change is read through `laravel-authorization`'s `AuthorizationMutation` accessors, never its
  properties, dispatched after its call commits, recorded under the code of its `operation()` (`role_created` to
  `guardrail_removed`, and `grant_expired` for a grantee's role, permission or policy and a role's permission that
  expired, `grant` naming which), correlated by its call (`authorization:{operation_id}`). `SystemOverrideUsed` is no
  mutation, so it is read from its own properties. Its actor is the call's: the identity behind the acting principal, as
  that principal; else the reference a trusted console command names; else explicitly no one, for system work (an
  expiry the pruner found, a write through a model outside the services), so the contributors never name the request's
  caller for what it did not do. Its subject is the mutation's `subject()`: the role, permission or policy; the grantee
  of a grant or boundary; the guardrail's tenant; the resource, or none for a whole type; and the overridden record. Its
  tenant is `tenant()`, by its key, and explicitly none for a platform-wide change. A change keeps names, the grant's
  application and subtree, its expiry as `auditProperties()` writes it (ISO 8601 in UTC), and whether the call was
  trusted; an update keeps the names of the fields it changed, never their values; a policy its document's version and
  digest, never the document.
- Decision this note records, beyond the plan's: six codes IAM-9.2 does not list record events `laravel-authorization`
  dispatches that are changes to who may do what: `role_exclusion_declared` and `_removed` (a pair of mutually
  exclusive roles, about its first role, keeping both names and the second role's reference), `grant_expiry_changed`
  (a grantee's or a role's grant's expiry changed), `resource_policy_attached` and `_detached`, and
  `system_override_used`. Leaving them unrecorded would leave a privilege change out of the change-management evidence
  IAM-9.3 keeps.
- A role, permission or policy deleted while grantees held it lists them (AUTHZ-15.2), a permission's roles among them,
  and its record covers every grantee beyond its subject as a bulk operation's subjects, through audit-log's
  `PendingRecord::covering()` on the builder its capture hands the mapper: each grantee once, read through the morph
  map, under audit-log's configured bounds, refused rather than truncated beyond them, and refused where the bound store
  keeps no attachment. A refusal is contained by audit-log's capture (`AuditCaptureFailed`), never thrown to the
  change's caller. A deletion that took no grant covers nothing, since audit-log refuses an empty bulk operation.
- Audit access (IAM-6.10). `Authorization\AuditAccessPolicyAdapter` answers audit-log's `AuditAccessPolicy`, bound
  shared over audit-log's `DenyAllPolicy` while `iam.adapters.authorization` is on, never mandatory. It decides the
  viewer's own tenant, its memberships and each tenant `laravel-authorization`'s access review names as the origin of a
  route giving one of the purpose's permissions (`ReviewQuery::holdings()->forAction()`, run trusted), each with
  `heldPermissionsFor()`, so a platform-wide or subtree grant counts wherever that tenant's decision says it reaches.
  Only a permission whose decision read no authentication requirement counts, since the policy is never told the
  reader's session. A
  principal is decided as its identity alone where `TenantAccess::mayActIn()` refuses it. The catalogue
  (`Authorization\PermissionCatalogue`) declares `audit-log.{purpose}`, `audit-log.{purpose}.{category}` and
  `audit-log.{purpose}.own`, and the scope is `tenants()` narrowed to the categories every tenant allows, else
  `onlyAbout()` the viewer in its `.own` tenants, else `none()`; never `all()`, `withTenantless()` or
  `exceptCategories()`.
- Administrative operations (IAM-6.9). The catalogue also declares SSO's and MFA's administrative operations
  (`Authorization\Enums\AdministrativeOperation`), reusing SSO's own names where it has them
  (`Freshness\Enums\FreshnessOperation`), and `Authorization\AdministrativeCheck::authorize()` checks one through
  `laravel-authorization` for the subject handed in, with the member's object (type, id or none for the type, tenant
  identifier) as the resource. The subject must be a resolved `Subject`: a bare principal or model is not taken, since
  `laravel-authorization`'s `for()` would complete it from the request's current subject, its session and its scope, an
  ambient read. The `Subject` is decided in the scope it names, and the request's scope is in place again afterwards:
  `laravel-authorization`'s `for()` decides a `Subject` naming a tenant in that tenant, and one naming none is handed to
  it marked as acting on the platform (`Subject::$platform`), which `for()` decides on the platform whatever tenant the
  request is in, so a subject built for a job or a command is decided where it acts, never in the request's tenant, and
  the request's own where the request is. A subject naming a tenant `laravel-authorization` cannot read is refused
  (`UnresolvedReferenceException`), never decided on the platform. Removing another identity's link is its own
  permission (`sso.link.remove_others`, AUTHZ-14.5). Re-enabling a factor disabled at its ceiling (`laravel-mfa`'s
  `Mfa::enableFactor()`, IAM-6.9's re-enable, recorded as `mfa.factor_enabled`) is `mfa.factor.enable`; requirement
  management is the application's own over its requirement contracts, declared as `mfa.requirements.manage` so it can be
  granted with the rest.

### Trail reads (IAM-9.9)

- Nothing in this package reads the audit trail. Inside the transaction `Iam::transaction()` opens on the storage
  connection, audit-log refuses a read before anything is queried (`AuditReadRefusedException`, reason
  `in_transaction`, naming the connection), since the read's record, or a row it would show, could still roll back;
  the same read once the transaction has committed is let in.
- That refusal holds only while audit-log's storage connection (`audit-log.storage.connection`, or under the outbox its
  outbox connection) is `iam.storage.connection`, or audit-log's bound store joins a transaction open there: audit-log
  checks only the connections it acknowledges a record on (`Querying\ReadGate`). This package aligns `authentication.`,
  `mfa.` and `sso.storage.connection` and `authorization.connection`, never audit-log's, which an application may put on
  a connection of its own; a read of the trail inside `Iam::transaction()` is then let in and queried on that
  connection.
- Decision this note records, beyond the plan's: IAM-9.9 rests on this package never reading the trail itself, not on
  audit-log's refusal, which is a second line only while audit-log stores on the storage connection. Audit-log's
  storage connection is left as the application chooses: the alignment (IAM-2.3, decision D4) names the members' keys,
  and audit-log's is none of them. `iam:check` notes an audit-log storage connection other than
  `iam.storage.connection` (`Checks\StorageCheck`), so an application that reads the trail inside its own changes knows
  the refusal does not cover it; nothing here writes or refuses audit-log's key.

## Success Path

- A person signs in through the session service on the `jwt` guard with `api` in `except_guards`: the mappers record
  the sign-in once, as `authentication.signed_in`, and audit-log's own capture of Laravel's `Login` records nothing.
- A password sign-in is two records, by and on the person, under the guard and the session, correlated by the
  session: `session.created`, keeping the method, then `authentication.signed_in`.
- An MFA step-up with an authenticator app, after one wrong code, is `mfa.verification_failed` (failed,
  `invalid_code`, by no one), `session.stepped_up` (the method and proof kind) and `mfa.verification_passed`, each in
  the session the step-up proved, correlated by it; a code factor's `mfa.code_sent` and its verifications are
  correlated by `mfa:{challenge}`.
- An SSO sign-in is `sso.authorization_request_started` (explicitly by no one), `sso.result_verified`,
  `sso.handoff_issued` and `sso.handoff_redeemed`, all correlated as `sso:{connection_id}:{request_reference}` in the
  connection's tenant, then `session.created` and `authentication.signed_in`, correlated by the new session, and
  `authentication.external_result_redeemed`, correlated with SSO's halves and naming the session: one sign-in, each
  half recorded once.
- A bearer request's guard holds the caller, and the application records `AuditLog::record('orders.shipped')`:
  audit-log reads the guard through this package's reader and fills the actor, the guard, the principal, the tenant and
  the session.
- An integrity check fails: audit-log dispatches `IntegrityCheckFailed`, and the application's listener of it pages
  the operator.
- A role created, assigned to two people and deleted is `authorization.role_created`, two
  `authorization.role_assigned` and `authorization.role_deleted`, each correlated by its own call, the deletion
  carrying both people as its manifest; a denied check is one `authorization.access_denied`, and an `authorize()` that
  throws one more, never two.
- A viewer granted `audit-log.count` in one tenant, a member of two, counts that tenant's entries alone, never the
  other's nor those with no tenant; a viewer granted nothing counts none.

## Failure / Edge Cases

- Without the exclusions, each sign-in, refused sign-in and sign-out on a `jwt` guard is recorded twice; `iam:check`
  refuses that configuration (`Checks\AuditCheck`, `install-and-check.md`).
- With them, an `api_key` guard's `logout()` and trusted `login()` are recorded by nothing, since only Laravel's event,
  which the exclusion leaves uncaptured, reports them.
- With them, a successful `attempt()` or `login()` on a `jwt` guard is recorded by nothing, since only Laravel's
  `Login`, which the exclusion leaves uncaptured, reports it; an application that signs people in that way rather than
  through the session service has no `authentication.signed_in` for them until `laravel-authentication` reports those
  sign-ins with an event of its own.
- A mapped record is written at once, never after a commit, and audit-log's `AuditRecorded` says an immediate write
  inside a transaction is durable only once that transaction commits. The members dispatch their reports of a change
  after their writes commit, so those are written once there is nothing left of the change to roll back, but
  `laravel-authentication` dispatches `AuthenticationFailed` at once, from inside whatever transaction is open. A
  refusal reported while a transaction is open on audit-log's storage connection is held and recorded once the
  outermost transaction there has ended, whichever way it ended (see Mapping), so a refused external sign-in is
  `authentication.sign_in_failed` and a refused external re-authentication `session.reauthentication_failed`, each once,
  correlated as `sso:{connection_id}:{request_reference}`, and a step-up or pending completion
  `laravel-authentication` refuses inside MFA's transaction is `session.step_up_failed` or
  `authentication.sign_in_failed` under `laravel-authentication`'s own reason, before MFA's `mfa.verification_failed`.
  A transaction that never ends inside the unit of work (one a long-running process leaves open) holds its refusals
  unrecorded, and a commit whose earlier callback throws drops them, as Laravel drops every callback after it. Every
  other mapped record is still written at once, and is lost when a transaction around its event rolls back.
- A mapper that throws (a reference over audit-log's 191 characters) writes nothing for that event, and audit-log
  dispatches `AuditCaptureFailed`, which the application can listen to; the flow that dispatched
  the event goes on.
- A provider registered for the first time once the application has booted is refused: audit-log takes no
  registration then, and a provider that mapped nothing would leave the members' events unrecorded in silence.
- Audit-log registered only from a later provider's `boot()` is registered with once the application has booted,
  before it freezes; audit-log never registered refuses the boot, naming its provider, except while a configuration
  command runs.
- A job dispatched by a caller on a `jwt` or `api_key` guard carries audit-log's actor, principal, tenant and session,
  so a record it leaves to the caller names who dispatched it; a guest's job carries none.
- Audit-log names each record with a UUIDv7 of the time the record says it occurred, which resets the process's one
  monotonic UUIDv7 state to that time, an earlier one included; a later id another member makes in the same
  millisecond can then sort before one it made just before. `laravel-authentication` orders proofs of one second by
  id, so the test suite starts each test from the present (`Tests\TestCase::setUp()`); the gap is audit-log's.
- A request carrying a bearer token the guard has not read yet fills nothing: the reader never resolves it.
- A record whose actor is set explicitly to no one keeps no caller's principal, tenant or session.
- A denial made inside a transaction on the storage connection that rolls back is recorded once, after the rollback;
  one inside a transaction that commits, once, after the commit.
- A deletion's manifest beyond audit-log's bounds, or where the bound store keeps no attachment, fails the record
  (`AuditCaptureFailed`); the deletion itself stands.
- An audit viewer whose grants reach more tenants than audit-log's scope holds, or named by a reference that names
  nobody, or holding grants in a tenant `laravel-authorization` cannot scope to, fails the read rather than see part
  of what it holds.
- A trail read inside a cross-member transaction is refused while audit-log stores on the storage connection; left to
  propagate, the refusal rolls the whole change back, as any failure of the work does. With audit-log on a connection
  of its own, the read is let in, and reads only what has committed there.
- Gaps in the members that the mapping works around:
  - Audit-log's `RecordPipeline` names a record with `Str::uuid7($occurredAt)`, which resets the process's one
    monotonic UUIDv7 state to that time, an earlier one included, so a later id made elsewhere in the same millisecond
    can sort before one made just before it; generating the id without a time, or building its bytes from the time
    without the shared generator, would close it.
  - `laravel-authentication` orders proofs of one second (`authenticated_at` has no fraction) by their UUIDv7 id
    (`Proofs\SessionProofs`), which breaks whenever anything rewinds that shared state; a time with microseconds, or a
    sequence for the tie, would close it.
  - MFA's event context has `tenant_id` and no tenant type, and SSO's `tenant_id` and `connection_tenant_id` none
    either; a morph class beside each would let a tenant be named through the morph map rather than as the one type
    `tenant`.
  - Audit-log's `Contribution` has no credential filler, so the credential IAM-9.7 lists comes from the mappers alone
    (`usingCredential()`); a `fillCredential()` with `usingCredential()`'s rule would let audit-log fill it.
  - Audit-log's check of a user left over on a guard in a job reads only a guard using Laravel's `GuardHelpers`, so
    this package still resets `laravel-authentication`'s guards before each job (IAM-11.3).
  - MFA's `EnrollmentAbandoned` names neither why the enrolment was abandoned (replaced, cancelled, an operator's reset,
    its confirmation attempts run out) nor the operator of a reset, so the mapper leaves its actor to the contributors;
    a cause and the reset's `Actor` on the event would let a reset name its operator from the event and the attempt
    ceiling be explicitly by no one.
  - `laravel-authentication`'s guards report a sign-in through `attempt()` or `login()` with Laravel's `Login` alone,
    never with an event of the package's, so once the guard is excluded from audit-log's capture nothing records it; an
    `AuthenticationEvent` for such a sign-in (or `SignedIn` without a session) would let the mapper record it as
    `authentication.signed_in`.
  - `laravel-authentication`'s `api_key` guard reports `logout()` with Laravel's `Logout` alone, and a trusted
    `login()` with `Login` alone, never with an event of the package's, so once the guard is excluded from audit-log's
    capture, as IAM-9.6 asks, nothing records them; an `AuthenticationEvent` for an API key caller's sign-out (and
    sign-in) would let the mapper record it as `authentication.signed_out` (and `authentication.signed_in`).
  - `laravel-authentication`'s `ContextualGuard` exposes no bound credential's id, does not say that `identity()`,
    `principal()`, `session()`, `scopes()` and `tenant()` resolve nothing once `hasUser()` is true, so the reader reads
    only a package guard, `AbstractGuard`, whose `user()` returns early; a bound-only snapshot of the caller would let
    it read any `ContextualGuard`.
  - `laravel-authorization` dispatches `usedBreakGlass` false on every decision until break-glass grants arrive
    (BL-70), so `authorization.break_glass_used` is defined and mapped but never recorded yet; and it dispatches
    `DecisionEvaluated` for every check, allows included, until configurable firing arrives (BL-72), so the mapper
    filters the decisions it records itself.

## Implementation Anchors

- `src/Audit/AuditRegistrations.php`: `register()`, `MAPPERS`, `CODES`, `REGISTERED`; `src/IamServiceProvider.php`:
  `boot()`; `src/Exceptions/MemberNotRegisteredException.php`: `forAuditTrail()`;
  `src/Audit/AuditSettings.php`: `mapsEvents()`, `MAPPERS`, `refusesUnregisteredCodes()`, `REQUIRE_REGISTERED`;
  `config/iam.php`: `audit.mappers`.
- `src/Audit/Mappers/AuthenticationEventMapper.php`, `MfaEventMapper.php`, `SsoEventMapper.php`: `map()`;
  `src/Audit/Mappers/Snapshot.php`: `ofAuthentication()`, `ofMfa()`, `ofSso()`, `describe()`, `attribute()`;
  `src/Audit/Mappers/Enums/Attribution.php`.
- `src/Audit/Enums/AuthenticationActivity.php`, `SessionActivity.php`, `MfaActivity.php`, `SsoActivity.php`:
  `definition()`, `properties()`; `src/Audit/Contracts/ListsProperties.php`.
- `src/Audit/Correlation.php`: `ssoSignIn()`, `mfaChallenge()`, `authenticationChallenge()`, `session()`,
  `authorizationOperation()`, `first()`, `MAX_BYTES`; `src/Audit/References.php`: `type()`.
- `src/Audit/AuthenticationActorReader.php`: `read()`; `src/Audit/References.php`: `of()`, `tenant()`, `TENANT_TYPE`;
  `src/IamServiceProvider.php`: `register()`.
- `src/Audit/CaptureExclusions.php`: `guards()`, `unexcludedGuards()`, `exceptGuards()`, `isGateCaptureOff()`,
  `holds()`, `DRIVERS`, `EXCEPT_GUARDS_KEY`, `GATE_KEY`.
- `src/Audit/Mappers/AuthorizationEventMapper.php`: `map()`; `src/Audit/Enums/AuthorizationActivity.php`:
  `definition()`, `properties()`.
- `src/Authorization/AuditAccessPolicyAdapter.php`: `scope()`;
  `src/Authorization/PermissionCatalogue.php`: `permissions()`, `audit()`, `auditCategory()`, `auditOwn()`,
  `CATEGORIES`; `src/Authorization/AdministrativeCheck.php`: `authorize()`, `decidedWhereItActs()`;
  `src/Authorization/Enums/AdministrativeOperation.php`: `member()`; `src/Authorization/AuthorizationSeams.php`:
  `seams()`.

## Authoritative Tests

- `tests/Feature/Audit/AuditRegistrationsTest.php` `testTheRegistrationsAreMadeBeforeTheFreezeInEveryOrder`,
  `testEachMembersInterfaceHasItsMapper`, `testAuditLogsOwnEventsAreNeverMapped`, `testNoCodeIsDefinedTwice`,
  `testAMembersEventIsRecordedOnce`, `testRegisteringAgainChangesNothing`,
  `testWithTheSwitchOffNothingIsMappedOrDefined`, `testALateRepeatedRegistrationRegistersNothingMore`,
  `testALateFirstRegistrationIsRefused`, `testAnAuditLogRegisteredFromALaterProvidersBootIsRegisteredOnceBooted`,
  `testAnAuditLogLeftOutRefusesBoot`, `testAnAuditLogLeftOutIsNotRefusedWhileAConfigurationCommandRuns`,
  `testOneCaptureListenerIsAdded`,
  `testWithTheSwitchOffTheRegistrationIsStillRecorded`
- `tests/Unit/Audit/Mappers/AuthenticationEventMapperTest.php` `testEachEventIsRecordedUnderItsCode`,
  `testNoiseIsSkipped`, `testEveryFlowIsProvidedFor`, `testARefusalIsRecordedByItsFlow`,
  `testOnlyARefusalWaitsForItsTransactionToEnd`,
  `testOnlyTheOwnCodesOfRefusalsKeepProperties`, `testASignInOutOfAttemptsIsALockout`,
  `testOnlyASignInOutOfAttemptsIsALockout`, `testAnAccountsOwnLimitIsNoLockout`,
  `testAConcealedSignInRefusalKeepsItsReasonConcealed`,
  `testAConcealedRefusalOfAnotherFlowIsConcealed`, `testARefusalsChallengeIsCorrelatedByWhoseItIs`,
  `testARedemptionsEventsAreCorrelatedAsTheSsoSignIn`, `testTheIdentitysOwnActionIsAttributedFromTheEvent`,
  `testTheIdentitysOwnActionIsTheIdentitys`,
  `testTheTypesAreReadThroughTheMorphMap`, `testAnEventNamingNoPrincipalOrTenantNamesNone`,
  `testWhatTheMemberDoesNotAttributeIsTheCallers`, `testWhatNoOneDidIsByNoOne`, `testEachEventKeepsWhatItsCodeKeeps`,
  `testTheCredentialUsedIsTheRecords`, `testAnEmptyCredentialIsNone`, `testACredentialManagedIsNeverTheRecords`,
  `testARecordLeftToTheCallerKeepsThePrincipalActedOn`, `testAnOwnActionKeepsNoPrincipalActedOn`
- `tests/Unit/Audit/Mappers/MfaEventMapperTest.php` `testEachEventIsRecordedUnderItsCode`,
  `testTheOutcomeIsTheEvents`, `testAnOperatorsActionIsTheOperators`, `testWhatMfaDidByItselfIsByNoOne`,
  `testAFailedVerificationIsByNoOne`, `testAnActionNamingNoOperatorIsTheIdentitys`,
  `testAnEnrolmentAbandonedIsTheCallers`, `testAChallengesEventsAreCorrelatedByIt`
- `tests/Unit/Audit/Mappers/SsoEventMapperTest.php` `testEachEventIsRecordedUnderItsCode`,
  `testTheOutcomeIsTheEvents`, `testAFlowIsAttributedToTheIdentity`,
  `testAnAdministrationEventIsTheActingIdentitysOnTheConnection`, `testADomainsAndAnEnforcementsSubjects`,
  `testWhatNoOneDidIsByNoOne`, `testAnAdministrationEventWithNoActingIdentityIsTheCallers`,
  `testAMigrationsLinkWithNoActingIdentityIsTheCallers`, `testAMigrationsLinkWithAnActingIdentityIsTheOperators`,
  `testALinkAFlowMadeIsTheIdentitys`, `testAnUnlinkedResultNeverRecordsItsGrant`
- `tests/Unit/Audit/Enums/AuthenticationActivityTest.php`, `tests/Unit/Audit/Enums/SessionActivityTest.php`,
  `tests/Unit/Audit/Enums/MfaActivityTest.php`, `tests/Unit/Audit/Enums/SsoActivityTest.php` `testEveryCodeIsPinned`,
  `testEachCodeIsUnderItsPrefixAndNoneIsAuditLogs`, `testEachDefinitionKeepsExactlyWhatItLists`,
  `testTheCatalogueTakesTheEnumTwice`
- `tests/Unit/Audit/CorrelationTest.php` `testEachSourcesFormat`, `testAMissingPartIsNoId`,
  `testAnIdIsAtMost191Bytes`, `testTheCapCountsBytes`, `testAnIdAuditLogWouldRefuseIsNone`,
  `testEveryIdIsOneAuditLogTakes`, `testTheFirstIdIsKept`
- `tests/Unit/Audit/ReferencesTest.php` `testTheMorphMapNamesAMappedClassByItsAlias`,
  `testATenantIsItsOpaqueIdentifier`, `testAReferenceTooLongToRecordIsRefused`
- `tests/Unit/Audit/AuditSettingsTest.php` `testTheKeyIsTheShippedConfigurations`,
  `testTheSwitchIsOffOnlyWhenItSaysSo`, `testUnregisteredCodesAreRefusedOnlyWhileTheRuleIsTrue`,
  `testTheRuleIsReadWhenAsked`
- `tests/Integration/Audit/RecordSequencesTest.php`, with the `jwt` guard excluded and `require_registered` on, at
  the connection's own level on SQLite, MySQL and PostgreSQL, then at READ COMMITTED and REPEATABLE READ on MySQL and
  PostgreSQL, `testAPasswordSignIn`, `testAnMfaStepUp`, `testAnSsoSignIn`, `testARefusedSsoSignIn`
- `tests/Integration/Audit/RefusedRedemptionsTest.php`, in audit-log's own tables on the storage connection, at the
  connection's own level on SQLite, MySQL and PostgreSQL, then at READ COMMITTED and REPEATABLE READ on MySQL and
  PostgreSQL, `testARefusedSignInIsRecordedOnceTheRedemptionHasRolledBack`,
  `testARefusedReauthenticationIsRecordedOnceTheRedemptionHasRolledBack`
- `tests/Integration/Audit/RefusedCompletionsTest.php`, in audit-log's own tables on the storage connection, the
  session revoked inside MFA's transaction once MFA has accepted the factor, at the connection's own level on SQLite,
  MySQL and PostgreSQL, then at READ COMMITTED and REPEATABLE READ on MySQL and PostgreSQL,
  `testARefusedStepUpIsRecordedOnceMfasTransactionHasRolledBack`,
  `testARefusedPendingCompletionIsRecordedOnceMfasTransactionHasRolledBack`
- `tests/Feature/Audit/AuthenticationActorReaderTest.php` `testARequestsRecordNamesTheCaller`,
  `testAQueuedJobRecordsTheDispatchingCaller`, `testAMappersActorForTheCallerGainsTheRest`,
  `testAGuestsRecordNamesNoOne`, `testAGuardHoldingNoOneIsNeverResolved`, `testATenantThatCannotBeLoadedIsLeftOut`
- `tests/Unit/Audit/CaptureExclusionsTest.php` `testEveryJwtAndApiKeyGuardIsFoundInOrder`,
  `testNoPackageGuardLeavesNothingToExclude`, `testWithNothingExcludedEveryPackageGuardIsMissing`,
  `testTheExclusionsKeepTheApplicationsAndAddTheMissing`, `testEveryGuardExcludedLeavesNoneMissing`,
  `testExcludingEveryGuardIsKept`, `testAMalformedExclusionListIsRefused`, `testGateCaptureIsOffOnlyWhileFalse`,
  `testGateCaptureLeftUnsetIsOff`, `testEverythingIsReadWhenAsked`, `testNothingIsWritten`
- `tests/Integration/Audit/NoDoubleRecordsTest.php`, at the connection's own level on SQLite, MySQL and PostgreSQL,
  then at READ COMMITTED and REPEATABLE READ on MySQL and PostgreSQL, in audit-log's own tables,
  `testASignInIsRecordedOnce`, `testARefusedSignInIsRecordedOnce`, `testASignOutIsRecordedOnce`,
  `testARefusedAttemptIsRecordedOnce` (each once with the guard excluded and twice without), and
  `testAnAttemptsSignInIsRecordedOnlyByAuditLogsCapture` (once without the exclusion, by audit-log's capture of
  `Login`, and not at all with it, pinning the gap of `laravel-authentication`'s listed above), and
  `testAnApiKeyGuardsSignOutIsRecordedOnlyByAuditLogsCapture` (once without the exclusion and not at all with it,
  pinning the `api_key` gap)
- `tests/Unit/Audit/Mappers/AuthorizationEventMapperTest.php` `testEachEventIsRecordedUnderItsCode`,
  `testEveryCodeIsProvidedFor`, `testEachSkippedEventRecordsNothing`,
  `testADenialIsTheSubjectsAndDeniedWithItsReason`, `testADenialForWantOfAStrongerProofIsRecorded`,
  `testADenialWithNoReasonIsDeniedWithNone`, `testOnlyADecisionWaitsForItsTransactionToEnd`,
  `testAGuestsDenialNamesNoOne`,
  `testAPreviewIsThePreviewersAboutThePrincipalPreviewed`, `testABreakGlassGrantUsedSucceeds`,
  `testADelegatedChangeIsTheCallersAndCorrelatedByItsOperation`,
  `testTrustedAndSystemChangesNameOnlyWhatTheCallNamed`, `testADeletionCarriesItsGranteesAsItsManifest`,
  `testADeletionIsRefusedWhereTheStoreKeepsNoAttachment`, `testAPermissionDeletionCoversItsRoles`,
  `testAGuardrailIsAboutItsTenant`, `testASystemOverrideIsTheCallersAboutTheRecord`,
  `testAChangeAboutNothingCoversEveryGrantee`,
  `testATenantNotKeyedByItsIdentifierIsRecordedWithNoTenant`, `testATenantOfAnotherTypeIsRecordedWithNoTenant`
- `tests/Integration/Audit/AuthorizationRecordsTest.php` `testARolesLifeIsRecordedCallByCall`,
  `testAPermissionGrantedAndRevokedIsTwoRecords`, `testEachDenialIsRecordedOnceAndNoAllow`
- `tests/Integration/Audit/AuthorizationTrailTest.php` `testAViewerNeverReadsBeyondItsScope`,
  `testADenialInsideATransactionIsRecordedOnceItEnds`
- `tests/Integration/Authorization/AuditAccessPolicyAdapterTest.php` `testATenantGrantIsSeenInItsTenant`,
  `testAPlatformGrantIsSeenInTheViewersTenantsThatAllowIt`, `testASubtreeGrantIsSeenInTheViewersTenantsBelowIt`,
  `testTheScopeIsNeverWiderThanAnyTenantsGrant`, `testAnOwnActivityGrantSeesOnlyTheViewersOwnActivity`,
  `testAPermissionWhoseDecisionReadsARequirementIsNotHeld`, `testAPrincipalsGrantsCountOnlyWhereItMayAct`
- `tests/Feature/Authorization/AuditAccessSeamTest.php`
  `testThePolicyIsBoundOverAuditLogsDefault`, `testTheSwitchOffKeepsDenyAll`
- `tests/Integration/Authorization/AdministrativeCheckTest.php` `testAGrantInTheObjectsTenantAllowsTheOperationThere`,
  `testADenialThrowsAndIsRecordedOnce`, `testARefusalForWantOfAProofOnNoSessionIsRecorded`,
  `testASubjectWithNoTenantIsDecidedOnThePlatform`, `testASubjectInATenantIsDecidedThereWhateverTheRequestsTenant`,
  `testASubjectInATenantThatCannotBeReadIsRefused`, `testATenantThatResolvesToNothingIsRefused`
- `tests/Unit/Authorization/PermissionCatalogueTest.php` `testEveryPermissionIsDeclaredOnceUnderItsMember`,
  `testSsosOwnNamesAreReused`, `testEachReadPurposeHasItsOwnPermissions`
- `tests/Integration/Audit/TrailReadsTest.php` `testAReadInsideACrossMemberTransactionIsRefused`,
  `testARefusalLeftToPropagateRollsTheChangeBack`, `testAReadOnAnAuditConnectionOfItsOwnIsLetIn`,
  `testTheSameReadAfterTheCommitIsLetIn`

## Change Triggers

- A member adds, renames or removes an event, a flow, a field or a context key: its mapper, its code and the code's
  definition follow, and so do the mapper's tests, which cover every event and flow.
- Audit-log ships a new code that means what a suite event means: the mapper reuses it, and this package's code goes.
- MFA or SSO gives its tenant a type, or audit-log offers a mapper an explicit guard, session or client: `References`
  and `Snapshot` follow.
- Audit-log lets a `HeldActor` carry a credential: the reader fills it from the guard, and the mappers' gap closes.
- `laravel-authentication` adds a driver whose guards dispatch Laravel's authentication events: `DRIVERS` gains it.
- `laravel-authentication` reports an `attempt()` or `login()` sign-in with an event of its own: the mapper records it
  as `authentication.signed_in`, and `testAnAttemptsSignInIsRecordedOnlyByAuditLogsCapture` expects one record either
  way.
- MFA gives `EnrollmentAbandoned` a cause and a reset's operator: the mapper names the operator from the event and
  records the attempt ceiling's by no one.
- `iam:check` changes what it enforces from `CaptureExclusions`' answers and
  `AuditSettings::refusesUnregisteredCodes()` (`install-and-check.md`).
- A member closes one of the gaps listed above: the workaround it names goes.
- Another member dispatches a refusal of its own at once, inside a transaction its caller may roll back: its mapper
  writes that refusal with `afterTransaction()` too.
- Audit-log or SSO adds an operational event: the guide's list gains it.
- `laravel-authorization` makes decision events configurable (BL-72), dispatches `usedBreakGlass` true (BL-70), or adds
  events or fields: the authorization mapper, its codes and `AuthorizationActivity`'s definitions follow.
- SSO or MFA names another administrative operation, or MFA adds a requirement operation:
  `AdministrativeOperation` gains or reuses its name.
