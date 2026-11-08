# Audit Mapping

## Purpose

This note describes how the package records `laravel-authentication`'s, MFA's and SSO's events in `laravel-audit-log`
(section 9 of the requirements, for authentication, MFA and SSO; authorization's events and codes wait for M11), and
what surrounds that mapping: the registrations made while the application boots, the one context contributor that fills
a record's gaps from `laravel-authentication`'s caller (IAM-9.7), the exclusions from audit-log's own capture that keep
a suite event from being recorded twice (IAM-9.6), the operational events offered to the application's alerting
(IAM-9.8), the refusal of a trail read inside a change that spans members (IAM-9.9), what M11 adds for authorization,
and the gaps in the members the mapping works around. Audit-log decides storage, integrity and retention; this package
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
- It registers `Audit\CallerContextContributor` with `AuditLog::contribute()` whatever `iam.audit.mappers` says: the
  contributor fills only gaps, of any record, the application's own and those of mappers the application binds itself
  included. Audit-log runs its own contributors first (the origin, the request, the actor), then this one, then any an
  application registers from a later provider's `boot()`.
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
  the builder, or `null` to skip; it never records, and never chooses a timing. The one exception is when a refusal is
  described, never what it says: see the next item.
- A refusal `laravel-authentication` reports while a transaction is open on audit-log's storage connection is recorded
  once the outermost transaction there has ended, whichever way it ended, never inside it. `laravel-authentication`
  dispatches `AuthenticationFailed` at once, from inside whatever transaction its caller opened, and several roll back
  on purpose once it has refused: this package's redemption of an SSO `sign_in` or `reauthenticate` code
  (`ExternalSignInRefusedException`, `ExternalReauthenticationRefusedException`), so the code stays unspent and SSO
  reports nothing; MFA's step-up and pending completion, whose adapters throw `not_accepted` on
  `laravel-authentication`'s refusal (`Mfa\StepUpAdapter`, `Mfa\PendingCompletionAdapter`), so MFA rolls its
  verification back and reports only its own `mfa.verification_failed`, never `laravel-authentication`'s reason; MFA's
  enrolment, which rolls back when its first code is refused; and any transaction the application opened. Audit-log
  writes a captured record at once, on its storage connection, which by default is the storage connection IAM-9.9's
  read refusal rests on, so a record written then would roll back with the transaction and leave no record of
  `laravel-authentication`'s refusal. So the authentication mapper hands every `AuthenticationFailed` it meets to
  `Audit\DeferredRefusals` (`defers()`), scoped to the request: with no transaction open on the storage connection
  (of those Laravel's transactions manager lets callbacks apply to, so not the one a testing trait wraps a test in) it
  holds nothing and the refusal is recorded at once; otherwise it holds the refusal and the mapper returns `null`, so
  audit-log neither writes nor claims the event. The refusal waits for the transactions open there: a rollback of any
  of them releases it at once (each is asked, since Laravel 12 does not tell a savepoint that has committed of its
  enclosing transaction's rollback), and a commit once the outermost transaction has committed and every callback
  queued on it has run (`Transactions\AfterConnectionCommits`); a release while a transaction is still open there (a
  savepoint rolled back inside another) waits again for those still open. Once none is, each refusal held, the same
  object, is handed in the order reported back to audit-log's capture (`Recorder::capture()`), where the mapper
  describes it from the event alone, as any other refusal. The record is written once, after the transactions have
  ended, however audit-log stores: a store that a rollback does not reach (a fake, a connection of its own) never gets
  it twice. A refusal an attempt the retry helper ran again reported is recorded too, since it reached every other
  listener as well.
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
  the actor whatever the attribution says.
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
- The guard, session and client are filled from the event before any contributor runs, through audit-log's fillers,
  since a mapper has no explicit setter for them; MFA's and SSO's application stands for the guard, which is the same
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
  so correlation never loses a record. `authorization:{operation_id}` is reserved for M11.
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
  are; M11's authorization code enum follows them, as `Audit\Enums\AuthorizationActivity`.
- Decision this note records, beyond the plan's: a refusal reported while a transaction is open on audit-log's storage
  connection is held and recorded once the outermost transaction there has ended (`Audit\DeferredRefusals`, not in the
  manifest), rather than written inside a transaction that may roll back, or copied and captured again after a
  rollback, which would record it twice wherever the rollback does not reach audit-log's store, or left to a dedicated
  audit-log connection, which IAM-9.9's refusal on the shared connection rules out as a requirement. It holds every
  such refusal, not only those reported inside a transaction this package rolls back on purpose, since MFA rolls its
  own transactions back around `laravel-authentication`'s calls too, and the application may: a window each call site
  had to open would leave the next one forgotten. A refusal reported inside a transaction that commits is recorded
  after the commit, beside the reports the members dispatch after it, rather than before them. The authentication
  mapper is the place the deferral is decided, since it is the only place that sees the event before audit-log writes
  it, and it reads only whether a transaction is open on audit-log's storage connection, never the request or the
  caller: what it records is still described from the event alone. IAM-9.5's "without dropping either" holds for a
  refused redemption with the one record `laravel-authentication`'s refusal gives, correlated as the SSO sign-in it
  ended, since SSO reports nothing for a code that stays unspent, and for a refused step-up or pending completion with
  `laravel-authentication`'s refusal, under its own reason, beside MFA's failed verification.

### The caller's context (IAM-9.7)

- `CallerContextContributor` is the one place an ambient read is the contract: audit-log hands it a `Contribution` at
  record time, and it reads only what a package guard already holds. It never calls `Auth::caller()` (which reads the
  request and may prove, and so revoke, a refresh token), never asks for the guard's authentication context (which
  reads proofs and runs contributors), and reads no request, cookie or header.
- It walks the guards audit-log walks for its own actor: `audit-log.actor.guards`, in order, or the default guard. A
  guard name `auth.guards` does not configure is no caller. The first guard that holds a user decides: it is asked
  `hasUser()` alone, which says only whether an identity is bound; when it is no package guard (`AbstractGuard`) it is
  audit-log's to read, or a `ContextualGuard` whose accessors promise nothing about resolving, and nothing is filled, so
  a later guard, which could name another person, is never read. Only once an identity is bound are a package guard's
  identity, principal, session and active tenant asked, which then answer what is bound without resolving anything
  (`AbstractGuard::user()` returns the bound identity first); a tenant the guard cannot load
  (`TenantUnavailableException`) is left open.
- Audit-log's actor contributor reads a user only from a guard using Laravel's `GuardHelpers`, which
  `laravel-authentication`'s guards do not, so on a `jwt` or `api_key` guard it leaves the actor open, and this
  contributor fills it.
- What it fills follows who the record is about. An open actor is the caller's: the actor, the guard, the principal,
  the tenant and the session are filled. An actor already the caller (a mapper's) gets the rest. An actor that is
  someone else, or explicitly no one (`by(null)`, as a mapper sets it for a failed sign-in or a sweep), gets nothing.
  Every filler fills only a field the record has not got, so an explicit value is never replaced.
- The caller is snapshotted as `laravel-authentication` snapshots it for its own events (its `EventContext`), and its
  references are made as the mappers make theirs (`Audit\References`): each type read through the application's morph
  map, and the tenant named by its tenant identifier under `References::TENANT_TYPE`, so the records a mapper
  describes and the ones this contributor fills name the same people. A caller audit-log cannot refer to (a type or
  identifier beyond its 191 characters) is no caller, and a guard name or session reference it cannot store is left
  open: audit-log loses a record whose contributor throws, and a gap is better than no record.
- In a queued job no guard holds the dispatcher's caller: the worker reset forgets every package guard's binding
  before each job (IAM-11.3), so a guard holding a caller there holds one the job bound itself. Audit-log carries no
  actor of a package guard's into the job either: its `CarryContextIntoJobs` takes the actor from its ambient actor,
  which reads a user only through `GuardHelpers`, and finds none on a `jwt` or `api_key` guard. So this package
  carries the caller itself (`Audit\CarryCallerIntoJobs`). As a job's payload is made (`ContextDehydrating`), the
  caller a guard holds (`Audit\HeldCaller`, the same read the contributor makes), or else, inside a job, the caller
  that job carried, so a chain of jobs keeps naming who started it, is carried as scalars under one hidden Context key
  (`Audit\CallerSnapshot::KEY`: the guard, the identity's and the principal's types and identifiers, the tenant
  identifier and the session identifier, never a secret), on the copy of Context the payload is made from; with none,
  the key is dropped, so a caller a sync job left in Context is not sent on, and guards that cannot be read (a driver
  that cannot be built) carry none rather than stop the dispatch, since audit-log's own carrying walks the same guards
  and reports the failure. It sits beside audit-log's envelope, whatever order the two listeners run in: audit-log
  carries an actor only from a guard this never reads.
- As the job starts (`JobProcessing`, once Laravel has hydrated Context from the payload) it enters a frame of
  `Audit\JobCallers` with the caller it carried, read back without trusting the payload (a missing, partial or
  malformed envelope is no caller); it leaves it as it ends (`JobProcessed`, `JobFailed`, `JobExceptionOccurred`), with
  any frame inside it. The frame is left from a listener registered once the application has booted, after every
  listener any provider's `boot()` adds, as audit-log leaves its own job frame: a record an application makes of a
  job's end, its failure or its retry is still inside both frames, with the job's origin and the caller it carried
  alike. While no guard holds a caller, the contributor fills from the innermost job's carried caller, under the same
  rules as a guard's, so audit-log's carried actor, when it is someone else, keeps the record. Outside a job none is
  read, so a request or command never takes a caller a sync job left in Context.
- `Audit\JobCallers` is frame state, as audit-log's execution frames are, not a unit of work's request state: it is
  scoped under its own class, outside the binding rule's `iam.scoped:` prefix, so the queue worker and Octane forget
  it at their own boundaries, while `Iam::resetWorkerState()`, which a long-lived loop calls between its units of
  work, even inside a job, keeps it, as it keeps audit-log's job frame, and the job's later records and the jobs it
  dispatches still name the caller it carried (`long-running-processes.md`).
- The credential IAM-9.7 lists is the mappers' alone (`usingCredential()`): audit-log offers a contributor no
  credential filler, and the guard exposes no credential's id.
- Decision this note records, beyond the plan's: the contributor is the one place an ambient read is the contract, and
  the one-core-method rule bounds it: it reads only `laravel-authentication`'s already-resolved caller, never a request
  and never anything that authenticates, and in a job only what the job's own payload carried. The carrying is this
  package's rather than a wait for audit-log, since every record a job leaves to a suite caller would otherwise name no
  one; audit-log reading a guard that hands its held identity would let its own carried actor name the caller, and is
  listed among the gaps below.

### No double records (IAM-9.6)

- `laravel-authentication`'s `jwt` guard dispatches Laravel's `Login`, `Failed` and `Logout` beside its own events,
  which the mappers record under audit-log's own codes; audit-log's listener of Laravel's events records each a second
  time unless the guard is in `audit-log.capture.laravel.except_guards`. `laravel-authorization` is always installed
  beside this package, so audit-log's Gate capture stays off.
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
- `Audit\CaptureExclusions` only computes, for `iam:install` to write and `iam:check` to enforce (decision Q5 (a)), and
  never writes configuration: `guards()` finds every guard of the `jwt` or `api_key` driver in the order
  `auth.guards` lists them; `unexcludedGuards()` those `except_guards` lacks (none under `['*']`); `exceptGuards()` the
  value to write, what the application excludes, in its order, then every guard still missing, `['*']` kept as it is;
  `isGateCaptureOff()` only while `audit-log.capture.gate.enabled` is `false` or unset; `holds()` both. An
  `except_guards` that is no list of guard names is refused, naming the key and never the value, rather than replaced
  or read as excluding nothing. Every value is read when it is asked, never kept.
- Audit-log's `definitions.require_registered` (IAM-2.5) is read the same way and never written:
  `AuditSettings::refusesUnregisteredCodes()` says whether it is on, which it is only while it is `true`, the one value
  audit-log reads as on, for `iam:install` to turn on and `iam:check` to enforce. With it on, a code no definition
  registers is refused rather than recorded under the permissive default; every code the mappers record is defined
  here or by audit-log, so the record sequences are pinned with it on.

### Operational alerts (IAM-9.8)

- `Audit\OperationalAlerts::listen()`, from `IamServiceProvider::boot()`, registers one listener of each of
  audit-log's `AuditWriteFailed`, `AuditCaptureFailed` and `IntegrityCheckFailed` and SSO's `KeyNearingExpiry`,
  whatever the configuration says. Each hands its event to the listeners `iam.audit.alerts` names for it
  (`audit_write_failed`, `audit_capture_failed`, `integrity_check_failed`, `key_nearing_expiry`): a class name or a
  list of them, read at each dispatch, resolved from the application current then (under Octane, the request's
  sandbox), and called through `handle()`, or invoked, synchronously and in order. The package sends nothing itself.
- A value that names no listener, and an `iam.audit.alerts` that is no map at all, is refused at the dispatch, never
  at boot, so a malformed cached configuration can still be cleared and a broken one is never read as naming none;
  `validate()` refuses it beforehand, with an alert that does not exist and a listener that is neither bound nor a
  class, for `iam:check`. What a listener throws propagates to the dispatch: audit-log reports a
  failure of its own events' listeners and goes on, and SSO's expiry report, a console command, fails.
- Audit-log dispatches `AuditWriteFailed` and `AuditCaptureFailed` inside its write guard, so a record their listener
  makes is refused. It raises `IntegrityCheckFailed` (from `audit-log:seal` and `audit-log:verify`) outside it, and
  SSO's `KeyNearingExpiry` knows no write guard, so a listener of either could record one, for an integrity failure
  into the very log just found altered or unverifiable. A listener alerts by other means, whichever event it hears.

### Authorization (M11)

- Nothing of `laravel-authorization`'s is mapped yet: its decision events and the codes they record wait for its
  marker interface and decision events (`laravel-authorization` #54 and #58). M11 adds a fourth mapper to
  `AuditRegistrations::MAPPERS` for that interface, a code enum under `authorization.*` (decisions under `security`,
  grants and role changes, privileges, under `access_management`, IAM-9.3) to `AuditRegistrations::CODES`, and the
  `authorization:{operation_id}` correlation `Correlation::authorizationOperation()` already reserves, so one guarded
  operation's decisions are found together. Audit-log's own `authorization.gate_denied` stays its own: Gate capture is
  off, so a decision is recorded once, by the mapper.

### Trail reads (IAM-9.9)

- Nothing in this package reads the audit trail. Inside the transaction `Iam::transaction()` opens on the storage
  connection, audit-log refuses a read before anything is queried (`AuditReadRefusedException`, reason
  `in_transaction`, naming the connection), since the read's record, or a row it would show, could still roll back;
  the same read once the transaction has committed is let in.
- That refusal holds only while audit-log's storage connection (`audit-log.storage.connection`, or under the outbox its
  outbox connection) is `iam.storage.connection`, or audit-log's bound store joins a transaction open there: audit-log
  checks only the connections it acknowledges a record on (`Querying\ReadGate`). This package aligns
  `authentication.`, `mfa.` and `sso.storage.connection`, never audit-log's, which an application may put on a
  connection of its own; a read of the trail inside `Iam::transaction()` is then let in and queried on that connection.
- Decision this note records, beyond the plan's: IAM-9.9 rests on this package never reading the trail itself, not on
  audit-log's refusal, which is a second line only while audit-log stores on the storage connection. Audit-log's
  storage connection is left as the application chooses: the alignment (IAM-2.3, decision D4) names the members' keys,
  and audit-log's is none of them. `iam:check` (M8) is the place to report an audit-log storage connection other than
  `iam.storage.connection`, so an application that reads the trail inside its own changes knows the refusal does not
  cover it; nothing here writes or refuses audit-log's key.

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
  audit-log's actor contributor finds no actor it can read, and this package's contributor fills the actor, the guard,
  the principal and the session from the guard.
- An integrity check fails: audit-log dispatches `IntegrityCheckFailed`, and the listener named in
  `iam.audit.alerts.integrity_check_failed` pages the operator.

## Failure / Edge Cases

- Without the exclusions, each sign-in, refused sign-in and sign-out on a `jwt` guard is recorded twice; `iam:check`
  refuses that configuration (M8).
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
  unrecorded, and a commit whose callback fails releases them only as the unit of work ends, as it releases the rest
  of the work held for that commit (`AfterConnectionCommits::settle()`). Every other mapped record is still written at
  once, and is lost when a transaction around its event rolls back.
- A mapper that throws (a reference over audit-log's 191 characters) writes nothing for that event, and audit-log
  dispatches `AuditCaptureFailed`, which `iam.audit.alerts.audit_capture_failed` can alert on; the flow that dispatched
  the event goes on.
- A provider registered for the first time once the application has booted is refused: audit-log takes no
  registration then, and a provider that mapped nothing would leave the members' events unrecorded in silence.
- Audit-log registered only from a later provider's `boot()` is registered with once the application has booted,
  before it freezes; audit-log never registered refuses the boot, naming its provider, except while a configuration
  command runs.
- A job dispatched by a caller on a `jwt` or `api_key` guard carries the caller in its payload, so a record it leaves to
  the caller (SSO's queued metadata refresh, a queued listener revoking sessions) names who dispatched it; a guest's
  job carries none, and its records name no one.
- Audit-log names each record with a UUIDv7 of the time the record says it occurred, which resets the process's one
  monotonic UUIDv7 state to that time, an earlier one included; a later id another member makes in the same
  millisecond can then sort before one it made just before. `laravel-authentication` orders proofs of one second by
  id, so the test suite starts each test from the present (`Tests\TestCase::setUp()`); the gap is audit-log's.
- A request carrying a bearer token the guard has not read yet fills nothing: the contributor never resolves it.
- A record whose actor is set explicitly to no one keeps no caller's principal, tenant or session.
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
  - Audit-log offers a mapper no explicit setter of the guard, the session or the client, only the fillers its own
    capture uses and its documentation reserves to the recorder and `Contribution`; the mappers fill through them.
  - `laravel-authentication` dispatches `AuthenticationFailed` at once, inside the caller's transaction, rather than
    once the outermost transaction on its storage connection has ended, and audit-log offers no capture that waits for
    a transaction to end whichever way it ends (`afterCommit` drops a record on rollback); either would let a refusal
    reported inside a transaction be recorded once it has ended without `DeferredRefusals`.
  - Audit-log's `Contribution` has no credential filler, so the credential IAM-9.7 lists comes from the mappers alone
    (`usingCredential()`); a `fillCredential()` with `usingCredential()`'s rule would let the contributor fill it.
  - Audit-log's `CachedUser` reads only a guard using Laravel's `GuardHelpers`, which `laravel-authentication`'s guards
    do not, so its actor contributor, and its check of a user left over in a job, cannot read a `jwt` or `api_key`
    guard, and its `CarryContextIntoJobs` carries no actor into a job such a caller dispatches; a small contract a
    guard could implement to hand its held user would remove the contributor's reason to fill the actor, and this
    package's reason to carry the caller into jobs itself.
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
    `principal()`, `session()`, `scopes()` and `tenant()` resolve nothing once `hasUser()` is true (the contributor
    therefore reads only a package guard, `AbstractGuard`, whose `user()` returns early, and no other `ContextualGuard`;
    a bound-only snapshot of the caller would let it read any), and `AuthManager::resolvedGuard()`, which gives a guard
    without building one, is `@internal`, so the contributor builds the guards audit-log's actor contributor already
    builds.

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
- `src/Audit/DeferredRefusals.php`: `defers()`, `MANAGER`; `src/Transactions/AfterConnectionCommits.php`: `run()`,
  `committed()`, `settle()`; `src/IamServiceProvider.php`: `registerRedemptionRecords()`.
- `src/Audit/Correlation.php`: `ssoSignIn()`, `mfaChallenge()`, `authenticationChallenge()`, `session()`,
  `authorizationOperation()`, `first()`, `MAX_BYTES`; `src/Audit/References.php`: `type()`.
- `src/Audit/CallerContextContributor.php`: `contribute()`; `src/Audit/HeldCaller.php`: `current()`;
  `src/Audit/References.php`: `of()`, `tenant()`, `TENANT_TYPE`.
- `src/Audit/CarryCallerIntoJobs.php`: `listen()`; `src/Audit/JobCallers.php`;
  `src/Audit/CallerSnapshot.php`: `of()`, `carriedIn()`, `carryInto()`, `forgetIn()`, `KEY`;
  `src/IamServiceProvider.php`: `register()`.
- `src/Audit/CaptureExclusions.php`: `guards()`, `unexcludedGuards()`, `exceptGuards()`, `isGateCaptureOff()`,
  `holds()`, `DRIVERS`, `EXCEPT_GUARDS_KEY`, `GATE_KEY`.
- `src/Audit/OperationalAlerts.php`: `listen()`, `validate()`, `KEY`, `EVENTS`; `config/iam.php`: `audit.alerts`.

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
- `tests/Feature/Audit/DeferredRefusalsTest.php` `testARefusalReportedWithNoTransactionOpenIsRecordedAtOnce`,
  `testARefusalReportedInsideATransactionIsRecordedOnceItCommits`,
  `testTheRefusalsAreRecordedInOrderOnceTheTransactionRollsBack`, `testOnlyARefusalIsHeld`,
  `testASavepointRolledBackWaitsForTheTransactionEnclosingIt`, `testARefusalHeldAgainKeepsItsPlace`,
  `testASavepointCommittedWaitsForTheTransactionEnclosingItToRollBack`,
  `testATransactionOnAnotherConnectionHoldsNothing`, `testTheTransactionATestIsWrappedInHoldsNothing`,
  `testWithNoTransactionsManagerNothingIsHeld`,
  `testARecordedRefusalIsHeldNoMore`
- `tests/Feature/Audit/CallerContextContributorTest.php` `testAnOpenRecordIsFilledFromTheCaller`,
  `testTheReferencesFollowTheMorphMap`, `testNothingTheRecordHoldsIsReplaced`, `testARecordAboutTheCallerGetsTheRest`,
  `testARecordAboutNoOneGetsNothing`, `testARecordAboutSomeoneElseGetsNothing`, `testAGuestFillsNothing`,
  `testItNeverTriggersAuthentication`, `testTheConfiguredGuardsAreWalkedInOrder`,
  `testTheWalkStopsAtAForeignGuardHoldingAUser`, `testAContextualGuardThatIsNoPackageGuardIsNeverRead`,
  `testAGuardNotConfiguredIsNoCaller`,
  `testADefaultThatIsNoNameIsNoCaller`, `testTheTenantIsNamedByItsIdentifierAndLeftOpenWhenUnavailable`,
  `testWhatCannotBeRecordedIsLeftOpen`, `testItFillsARecordThroughAuditLog`, `testItIsRegisteredWithTheMappersOff`
- `tests/Feature/Audit/CarryCallerIntoJobsTest.php`, each job run from its payload as a queue worker runs it,
  `testACallerRecordInAQueuedJobIsTheDispatchingCallers`, `testAJobDispatchedFromAJobCarriesTheCallerOn`,
  `testAGuestsJobCarriesNoCaller`, `testTheCarriedCallerEndsWithItsJob`, `testACallerLeftInContextIsNotSentOn`,
  `testThePayloadCarriesTheCallerBesideAuditLogsEnvelope`, `testAGuardThatCannotBeBuiltStillQueuesTheJob`,
  `testACallerTheJobBindsItselfBeatsTheCarriedOne`,
  `testAJobsFrameIsLeftHoweverItEnds`, `testARecordOfAQueuedJobsEndIsTheDispatchingCallers`,
  `testARecordOfAJobsEndIsTheCarriedCallersHoweverItEnds`, `testAResetInsideAJobKeepsTheCarriedCaller`,
  `testTheJobCallersAreScopedAndKeptByTheExplicitReset`
- `tests/Unit/Audit/JobCallersTest.php` `testOutsideAJobThereIsNoCaller`, `testTheInnermostJobsCallerIsInForce`,
  `testLeavingAJobLeavesTheJobsInsideIt`, `testTheInnermostFrameOfAJobIsLeft`, `testLeavingAgainChangesNothing`
- `tests/Unit/Audit/CallerSnapshotTest.php` `testTheCallerIsTheEventContexts`,
  `testAContextNamingNoGuardOrIdentityIsNoCaller`, `testACarriedCallerIsReadBackExactly`,
  `testAContextCarryingNoCallerCarriesNone`, `testAMalformedEnvelopeIsNoCaller`, `testTheOptionalPartsMayBeLeftOut`,
  `testForgettingTheCallerLeavesTheRest`
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
- `tests/Feature/Audit/OperationalAlertsTest.php` `testEachEventReachesItsListenersInOrder`,
  `testAListenerNamedAloneHearsOnlyItsEvent`, `testWithNoListenerNamedNothingIsSent`,
  `testTheListenersAreReadAtEachDispatch`, `testTheSandboxsListenerIsHanded`, `testAMalformedValueRefusesTheDispatch`,
  `testAlertsThatAreNoMapRefuseTheDispatch`, `testAListenerThatCannotBeHandedTheEventIsRefused`,
  `testAListenersFailurePropagatesToTheDispatch`, `testAGuardedFailuresListenerCannotRecord`,
  `testAnUnguardedEventsListenerCouldRecord`, `testAWellFormedConfigurationIsValid`,
  `testValidateRefusesAMalformedConfiguration`
- `tests/Integration/Audit/TrailReadsTest.php` `testAReadInsideACrossMemberTransactionIsRefused`,
  `testARefusalLeftToPropagateRollsTheChangeBack`, `testAReadOnAnAuditConnectionOfItsOwnIsLetIn`,
  `testTheSameReadAfterTheCommitIsLetIn`

## Change Triggers

- A member adds, renames or removes an event, a flow, a field or a context key: its mapper, its code and the code's
  definition follow, and so do the mapper's tests, which cover every event and flow.
- Audit-log ships a new code that means what a suite event means: the mapper reuses it, and this package's code goes.
- MFA or SSO gives its tenant a type, or audit-log offers a mapper an explicit guard, session or client: `References`
  and `Snapshot` follow.
- Audit-log adds a credential filler to `Contribution`, or a way to read a guard's user that `laravel-authentication`'s
  guards satisfy: the contributor's credential gap, or its reason to exist for the actor, changes, and with the latter
  `CarryCallerIntoJobs` may leave the actor to audit-log's own carried envelope.
- `laravel-authentication` adds a driver whose guards dispatch Laravel's authentication events: `DRIVERS` gains it.
- `laravel-authentication` reports an `attempt()` or `login()` sign-in with an event of its own: the mapper records it
  as `authentication.signed_in`, and `testAnAttemptsSignInIsRecordedOnlyByAuditLogsCapture` expects one record either
  way.
- MFA gives `EnrollmentAbandoned` a cause and a reset's operator: the mapper names the operator from the event and
  records the attempt ceiling's by no one.
- `iam:install` and `iam:check` (M8) write and enforce `CaptureExclusions`' answers and
  `AuditSettings::refusesUnregisteredCodes()`, and call `OperationalAlerts::validate()`.
- A member closes one of the gaps listed above: the workaround it names goes.
- `laravel-authentication` reports a refusal once the outermost transaction has ended, or audit-log offers a capture
  that waits for a transaction to end either way: `DeferredRefusals` goes, and `RefusedRedemptionsTest` and
  `RefusedCompletionsTest` still expect each refusal recorded once.
- Another member dispatches a refusal of its own at once, inside a transaction its caller may roll back: its mapper
  hands that refusal to `DeferredRefusals` too.
- Laravel changes which transactions its transactions manager lets callbacks apply to, or when it runs a transaction's
  rollback callbacks: `DeferredRefusals::defers()` and its tests follow.
- Audit-log or SSO adds an operational event: `OperationalAlerts::EVENTS` and `iam.audit.alerts` gain it.
- `laravel-authorization`'s decision events are mapped (M11): its mapper and codes join the registrations, its
  operations' correlation comes into use, and Gate capture's requirement is re-read against them.
