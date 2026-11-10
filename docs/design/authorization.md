# Authorization

## Purpose

This note describes how the package binds `laravel-authorization` to the other members (FEATURES section 6): its subject
resolver, answered from `laravel-authentication`'s caller (IAM-6.1); its authentication context,
`laravel-authentication`'s, with the `mfa` and `sso` namespaces (IAM-6.2); its requirement checker, answered by MFA's
requirement check on the proofs of the subject's own session (IAM-6.3); its insufficient-authentication exception,
rendered as MFA's step-up (IAM-6.4); its session policy source and `laravel-authentication`'s scope registry, answered
from the caller's credential scopes and from `laravel-authorization`'s registry (IAM-6.5); and
`laravel-authentication`'s application access, answered from `laravel-authorization`'s grants (IAM-6.6). It covers how
the binding rule keeps a class the application names in `laravel-authorization`'s configuration, when the access
contracts are mandatory, and the gaps in the members the adapters work around. It then covers the second part of this
work: the grants and the tree (IAM-6.7, IAM-6.8, IAM-7.5), the permission catalogue and the audit access policy
(IAM-6.9, IAM-6.10), forgetting the decisions that depended on authentication (IAM-6.11), and
`laravel-authorization`'s operations: its connection, its prune, its check, its request state and its resource tenants
(IAM-2.3, IAM-2.6, IAM-10.1, IAM-11.3). Group mapping is in `provisioning-and-tenancy.md` and the authorization audit
codes in `audit-mapping.md`. The rule itself is in `binding-precedence.md`, and the worker reset in
`long-running-processes.md`.

## Invariants

- The seams, and the default each replaces, all declared in `Authorization\AuthorizationSeams` and switched by
  `iam.adapters.authorization`:

  | Member seam                              | Bound to                                     | Member default replaced      | Lifetime  | Also needs         |
  |------------------------------------------|----------------------------------------------|------------------------------|-----------|--------------------|
  | AUTHZ `SubjectResolver`                  | `Authorization\SubjectResolverAdapter`       | `AuthGuardSubjectResolver`   | scoped    |                    |
  | AUTHZ `AuthenticationContext`            | `Authorization\AuthenticationContextAdapter` | `GuardAuthenticationContext` | transient |                    |
  | AUTHZ `AuthenticationRequirementChecker` | `Authorization\RequirementCheckerAdapter`    | `RefusingRequirementChecker` | transient | `iam.adapters.mfa` |
  | AUTHZ `SessionPolicySource`              | `Authorization\SessionPolicySourceAdapter`   | `NoSessionPolicy`            | transient |                    |
  | AUTH `ScopeRegistry`                     | `Authorization\ScopeRegistryAdapter`         | `AcceptAnyScope`             | transient |                    |
  | AUTH `ApplicationAccess`                 | `Authorization\ApplicationAccessAdapter`     | `AdmitAnyPrincipal`          | scoped    |                    |
  | AUTHZ `IdentityDirectory`                | `Authorization\IdentityDirectoryAdapter`     | `GuardUserIdentityDirectory` | transient |                    |
  | AUTHZ `TenantTree`                       | `Authorization\TenantTreeAdapter`¹           | `FlatTenantTree`             | scoped    |                    |
  | AUTHZ `GrantHook`                        | `Authorization\GrantHookAdapter`             | `GrantHooks` (composite)     | transient | `iam.adapters.sso` |
  | AUDIT `AuditAccessPolicy`                | `Authorization\AuditAccessPolicyAdapter`     | `DenyAllPolicy`              | shared    |                    |

  ¹ Only while the application names or binds a tree; otherwise the row binds `laravel-authorization`'s own
  `FlatTenantTree`, decided as each request or job first resolves the seam (`TenantTreeAdapter::forApplication()`,
  through the row's `SeamBinding::$factory`): `laravel-authorization` tells a flat application by the class of the tree
  bound, never by its answers alone, and takes any other tree down its hierarchical paths, which in `whereAuthorized()`
  nest the subtree query and refuse one on another connection than the scoped model's.

  The grant half of SSO's principal scope, this package's own port (`Tenancy\Contracts\GrantScope`), is bound beside
  them by the service provider, not as a seam: `Authorization\GrantScopeAdapter`, with `bindIf()`, while the switch is
  on, and `Tenancy\UnknownGrantScope`, with `singletonIf()`, while it is off (`provisioning-and-tenancy.md`).

  The subject resolver, the context and the requirement checker are never mandatory: each default refuses (no tenant,
  every requirement unmet) rather than admits. Nor are the identity directory and the tree: an incomplete directory
  leaves the grant scope query `unknown` and has every grant to an identity reported as widening, and a flat tree
  reaches no tenant below, each narrower than the adapter, never wider. Nor is audit-log's access policy, whose default
  shows nobody anything. The grant hook is mandatory while SSO links people by a verified domain
  (`sso.features.domain_linking`): left on `laravel-authorization`'s composite then, a grant that takes a person beyond
  a tenant would leave their link by that tenant's domain active. The session policy source's default caps no person and
  allows nothing only to a machine principal carrying `AuthorizableMachine`, so a `laravel-authentication` machine
  without that marker is capped by nothing; it and the scope registry are mandatory while a guard accepts `api_key` or
  `client_credentials`, as the bound application policy says, and application access while
  `authorization.application_access` maps an application (`Authorization\AccessMandates`). `laravel-authentication`'s
  tenant access is not `laravel-authorization`'s to answer (AUTHZ-13.8), and stays on `OwnTenantOnly`.
- The subject resolver is scoped, as `laravel-authorization`'s own default is: its resolved tenant is kept for the
  request only while `ResolvedTenant::isFrom()` finds the resolver bound to be the very one that resolved it, by
  identity. A transient resolver would resolve the subject again on every tenant-scoped read (`TenantScope::scopeKey()`,
  `currentChain()`, the tenant scope on its roles, permissions and policies), and each new tenant, bound with
  `instance()`, fires `laravel-authorization`'s rebinding listener, which empties the request's resolution memo, so
  every check would read its grants again. The adapter still reads `Auth::caller()` afresh on each call.
- The tenant tree is scoped for the same reason: `laravel-authorization` keeps a tenant's chain only while the tree bound
  is the instance it read it from (`ResolvedTenant::chain()` reads again when its first entry is not that tree, and
  `TenantChain::tree()` resolves the contract on every `TenantScope::currentChain()`), and keys its batch memo of tree
  reads (`ResolutionCache::answerTree()`) by `spl_object_id()` of the tree. A transient tree would walk the
  application's tree, and resolve the tenant and every ancestor through the tenant resolver, again on every check and
  every query on a tenant-scoped model; `TenantTreeAdapterTest::testACheckReadsTheTreeOncePerUnitOfWork` pins one
  `ancestors()` read for a check. It holds nothing itself, and the worker reset forgets it with the rest of
  `iam.scoped:`.
- `laravel-authorization` binds each default only where nothing is bound yet (`bindIf()`, since
  laravel-authorization#129): its provider scopes the class its configuration names under `authorization.default:` and
  the contract, and binds the contract to a closure it declares that resolves that key. So each of its rows names the
  provider and the default class (`AuthorizationSeams::authorizationRow()`), and the seam is replaced only while it is
  unbound or holds that closure. A class the application names in `authorization.subject_resolver`,
  `authorization.requirement_checker`, `authorization.session.source`, `authorization.identity_directory` or
  `authorization.tenant_tree` is the application's, and kept: the row names that key
  (`SeamBinding::$configurationKey`), and the rule reads it as `laravel-authorization` will
  (`SeamBinding::namesApplicationClass()`), leaving the seam for `laravel-authorization` to bind to that class whichever
  registers first. No key names the grant hook's class: `laravel-authorization` binds the composite
  `GrantHooks::fromConfig()` builds from `authorization.grant_hooks`, so its row names `GrantHooks` beside the provider.
  Anything the application binds over the contract is kept too, made before this package registers or after, and a
  `laravel-authorization` that registers after this package, with the other providers or from another provider's
  `boot()`, leaves the adapters bound.
- `laravel-authorization` empties the resolution memo when the subject resolver or the tenant tree is bound again
  (`forgetResolutionsOnRebinding()`), in every provider order: where the seam is still unbound as it registers it
  listens at once, and where this package bound the adapter first it listens from the seam's first resolution in each
  container, the earliest a rebinding could change anything memoised. So the rows name no listener of their own, and
  each seam has exactly one listener once resolved.
- The subject (`SubjectResolverAdapter`). `resolve()` takes nothing, so it reads the request's caller
  (`Auth::caller()`): the principal, its identity, the active tenant, the guard as the application and the session's
  key. No caller, or a pending session that has not chosen its principal, is no subject. `forUser()` is handed the model
  Laravel's Gate decides about (`Auth::user()`, the identity) or one the caller names, and never reads `Auth::caller()`:
  application access asks it while `laravel-authentication` admits a sign-in, a refresh or a switch, and reading the
  caller then would prove the request's credential again mid-admission, a refresh credential's replay detection
  included, and keep the answer on the request for the rest of it. It reads the default guard's state instead, only
  where the guard has already resolved its user (`hasUser()`): a model that is the guard's principal, or the identity
  acting as it, the very object or the same model loaded again (`Model::is()`, as the session policy source compares a
  principal), is the caller with the guard's tenant and session; any other principal is a subject in its own tenant
  with no session; any other model, an identity that is not the caller's and no principal among them, is its own
  subject and identity, with no tenant and no session, as `laravel-authorization`'s own resolver and
  `Subject::withSubject()` answer it, so a check about such an identity counts only its own grants and the grant hook's
  classifier finds it the recipient of a grant made to it (`WideningClassifier::recipient()` asks `forUser()`; grants to
  an identity are a grantee kind of their own, AUTHZ-2.2). A default guard that is not one of
  `laravel-authentication`'s is answered by `laravel-authorization`'s own resolver, so an admin panel on a Laravel
  session guard decides as it did before, except that a `laravel-authentication` principal, the guard's user or one
  handed in, is still mapped to its identity and its own tenant, with that resolver's application, guard and session:
  application access, `authorization:why` and `Gate::forUser()` all build their subject through `forUser()`, and a
  sign-in or refresh route names no guard, so a principal answered as its own identity in no tenant there would lose
  its identity's grants, denials, boundaries and inactive state only because another guard was the default.
  `laravel-authentication` keeps the caller on the request's attributes, and a queue worker's jobs share one request,
  so the worker reset drops those attributes between units of work (`WorkerReset::forgetMemberState()`,
  `long-running-processes.md`): without it every later job would be decided about the first job's caller.
- The context (`AuthenticationContextAdapter`). Its namespaces are a fixed list, `authentication`, `mfa` and `sso`:
  `laravel-authorization` reads them as it boots and builds its key catalogue once, both before this package registers
  its `mfa` and `sso` contributors once every provider has booted, and a namespace missing then would leave its
  assurance keys testable for good; one that holds no keys costs nothing. The values are
  `AuthenticationContexts::current()->toArray()` for those namespaces, `[]` for a guest, `laravel-authentication`'s key
  names untouched. A namespace an application's own contributor adds is not supplied. It is scope invariant. Its
  assurance keys (`assuranceKeys()`, `ASSURANCE_KEYS`), beside `laravel-authorization`'s own (`amr`, `auth_time`,
  `multifactor`, `seconds_since_step_up`), are the names that say how strongly or how recently the session was
  authenticated: `laravel-authentication`'s `mfa` and `recovery_code`, MFA's verdicts (`accepted`, `factor_types`,
  `level`, `phishing_resistant`, `user_verification`, `last_verification_age_seconds`) and SSO's record of the
  provider's authentication (`provider_auth_time`, `provider_amr`, `provider_acr`, `provider_authn_context_class_ref`).
  `laravel-authorization` makes a key of any of the three namespaces any segment of which is one of them untestable,
  and refuses a policy that tests or references one, on write and on read, so a policy states an
  `authentication_requirement` instead. Each is an exact name, not the prefix form: SSO's `provider_session_deadline`,
  which a policy may test, shares the `provider_` prefix. Like the namespaces, they are fixed for the life of the
  process.
- The keys (`AuthenticationContextKeys`). Each key of the three namespaces is declared on `laravel-authorization`'s key
  catalogue with its type, once, as the catalogue is built, while the context bound is this package's: a policy reads
  only a declared key, and the context's contract carries no types. Each is declared testable; the catalogue makes the
  assurance keys untestable, whatever they are declared as. A key already declared, by `authorization.context.keys` or
  an attribute provider, keeps its declaration.
- The requirement checker (`RequirementCheckerAdapter`) reads nothing of the request or the guard:
  `laravel-authorization` hands it the subject, carrying its session. The session is the subject's guard's, found by
  its key through the subject's identity's own sessions on the write connection (`CurrentSession::named()`), so another
  identity's session is never judged. The subject must be accounted for by that identity, as `laravel-authorization`'s
  contract asks (a checker confirms the proofs belong to `$subject->subject`): a principal must act for it, and any
  other subject must be it, or name no identity, when it is its own (`identityOf()`). So a principal acting for another
  identity, and any other model or object paired with another identity's session, are refused, since a `Subject`
  reaches the checker as it was built, through `Authorization::for()`, `scopedTo()`, an acting context or the grant
  scope query, not only through the resolver. The session must act in the subject's tenant too (`inTenantOf()`, the
  subject's tenant identifier against `Session::getTenantId()`), so one tenant's provider trust
  (`ProviderTrust::accepted()`) is never applied to a principal in another. The identifier is read by `tenantOf()`: a
  tenant of `laravel-authentication`'s names itself (`getTenantIdentifier()`), and any other is read as
  `laravel-authorization` reads a tenant (`TenantScope::extractTenantPair()`), by its key, since
  `AuthorizationScope::subjectIn()` hands the checker the request's subject with the scope's tenant as
  `laravel-authorization`'s own `Reference` for every listing in a scope (`permissionsFor()`), which must decide as the
  check does. A session records its tenant's key alone, so only the key is compared; a tenant that cannot be read is
  refused. An identity MFA reads as inactive (its bound `ActiveStateResolver`, which this package answers from
  `laravel-authentication`'s active state, or the identity's own `isMfaActive()` where that has none) meets no
  requirement, every part unmet and no proof read, as MFA's contract has it and its route gate answers
  (`EnsureMfaRequirementIsMet::isMet()`), so a session that stepped up before its identity was suspended or deactivated
  meets nothing, and an `authorize:` statement guarded by a requirement and MFA's `mfa:` route gate give the same
  answer. The first
  factor and the further proofs since the oldest time a part's maximum age allows are read through
  `Auth::sessions($guard)`, handed the session itself, at most `RequirementSubject::MAX_LIMIT`, translated and filtered
  as the proof store's are (`SignInProofs`), and judged by MFA's requirement check, newest proof per part. The further
  proofs are every kind a requirement can be met with, a reauthentication at an external provider
  (`external_reauthentication`) included (`RequirementCheckerAdapter::FURTHER_KINDS`): the authentication requirement
  check leaves that kind out only because `laravel-authentication` counts it through its external evidence policy
  first, and `laravel-authorization` has no such policy, so the checker reads what MFA's route gate reads
  (`ProofStoreAdapter::proofs()`), and a provider's proof names its connection to MFA only under the evidence SSO
  accepted and the trust of the session's tenant (`ProviderTrust::accepted()`). A pending, revoked or ended session has
  no proofs, and meets nothing. It is scope invariant.
- The requirement crosses one part for one (`Authorization\Translation\RequirementTranslator`): `phishing_resistant`
  is MFA's `phishing_resistance` and `assurance_level` its `minimum_level`; the level is MFA's (`aal1`, `aal2`, `aal3`),
  named exactly as MFA names it, and any other (`unclassified` included) is refused, so the test is undecidable rather
  than judged at the nearest level. MFA's evaluation crosses back as met, with its `metUntil`, or unmet, with the parts
  named and ordered as `laravel-authorization` names and orders them.
- The step-up (`InsufficientAuthenticationMapping`). Laravel turns an authorization exception into an HTTP exception
  before any render callback is asked, so the callback registered on Laravel's handler is asked about the HTTP
  exception, and maps it only when the exception it was made from is `laravel-authorization`'s. Laravel hands it the
  request alone, and MFA's own reader turns that into MFA's caller (`CallerContext::fromRequest()`); the caller's
  session is the key the bound subject resolver names for the request, the one `laravel-authorization` decided the
  caller's checks on, read in the callback because nothing hands it to one. The core, `stepUp()`, takes the caller, that
  session and the refusal as plain values. Only a refusal decided on the caller's own session is mapped
  (`isDecidedOn()`): its decision's `RequirementFreshness::$session`, the session's fingerprint, must be the caller's
  session's, fingerprinted as `laravel-authorization` fingerprints one. A refusal about a subject the caller names
  (`Authorization::for($account)->authorize()`) was decided on no session, so `laravel-authorization` found every part
  unmet without asking, and no step-up by the caller could ever meet it; mapped, it would send the client into a
  step-up it can never complete, so it stays Laravel's 403, as `laravel-authorization` keeps the exception plain for a
  preview for the same reason. The first candidate MFA can express is asked for, whole, with the
  factors MFA offers the caller and whether its identity holds a confirmed factor (`Mfa::factors()`), and the handler
  renders MFA's exception as the application renders it. A refusal none of whose candidates MFA can express stays
  Laravel's 403. It is registered while both the authorization and MFA switches are on, on Laravel's own handler only.
- The session policy (`SessionPolicySourceAdapter`). `laravel-authentication` keeps a credential's scopes on the guard
  that admitted it alone (`ContextualGuard::scopes()`), and neither its caller nor `laravel-authorization`'s subject
  carries them, so this one read is ambient, and its docblock says why. It reads only the guard the subject names, never
  the default one, afresh on every call, and only while that guard holds the subject now: its current principal is the
  subject, the same object or the same model, and, where the subject carries a session, its current session is that
  session, compared by key as text. Any other subject, a principal the caller names (`Authorization::for()`) or another
  of the principal's sessions among them, is no credential the guard holds, and is answered `null`, no cap, as the
  contract asks of a named person; so is a person naming no guard, or a guard that is not one of
  `laravel-authentication`'s. A person's session answers `null` from the guard itself, an API key or client-credentials
  token its scopes, `[]` allowing nothing. A machine whose credential the guard does not hold is answered `[]`, never
  `null`: `laravel-authorization` allows nothing to a machine answered `null` only when it carries its own marker
  (`AuthorizableMachine`), and caps any other subject by nothing, while `laravel-authentication`'s machines are its
  `MachineIdentity`. So a subject that is a machine identity, whose identity is one, or a principal acting for one, is
  capped to nothing wherever no credential of its own caps it, marker or not, and a machine never borrows scopes it was
  not issued nor goes uncapped for want of them. A subject the Gate hands over outside the route whose guard admitted
  it names the default guard (`forUser()`), which does not hold it, so a machine is allowed nothing there either:
  closed, never open. The guard is read only once it has resolved its request (`hasUser()`): one that has not, or is
  still admitting it, holds no credential the source may read, so its subject is answered as one the guard does not
  hold, and the guard's resolution is never started, or entered again, from here.
- The scope registry (`ScopeRegistryAdapter`). Each scope is asked of `laravel-authorization`'s registry alone, and every
  one it does not accept is rejected, in the order given, so `laravel-authentication` refuses to issue or rotate the
  credential. The registry is the application's binding of `laravel-authorization`'s contract where it binds one, and
  otherwise the `CatalogueScopeRegistry` `laravel-authorization` ships and binds nowhere: a scope the scope map
  (`authorization.session.scopes`) names, a declared permission, or a pattern covering one. It is resolved on every
  call, since the shipped one holds the scope map, which `laravel-authorization` builds once a request or job, so the
  adapter never keeps one request's map for the next. Neither the guard nor the principal changes the answer.
- Application access (`ApplicationAccessAdapter`). `laravel-authorization`'s `Services\ApplicationAccess` decides about
  the principal handed in, in the principal's own tenant (`null` for a platform principal), on the application asked
  about, never the request's caller or its active tenant: a sign-in, a switch or a refresh asks about a principal that
  is not yet, or no longer, the request's. The principal becomes the subject through `forUser()`, which reads no caller,
  so a guard asking while it admits is never entered again; `laravel-authentication` asks inside
  `WriteConnection::during()`, so the grants are read from the primary. `laravel-authorization` decides it without
  session caps, since a principal being admitted holds no session yet: neither the request's credential scopes nor a
  machine's missing ones refuse it, so a machine is admitted on its grants as a person is, while a deny, a boundary, a
  guardrail or an explicit `capped()` cap still refuses. An application the map does not name is open to every
  principal, people included, whatever its grants, as `laravel-authorization` decides (`mayUse()` answers `true` for
  it), and the adapter changes nothing of that. The adapter keeps nothing, but is bound scoped under `iam.scoped:`, as
  IAM-6.6 asks.
- The mandates (`AccessMandates`), declared by the binding rule as it applies and read by `iam:check` as it runs: the
  scope registry is mandatory while any configured guard accepts `api_key` or `client_credentials`, since left on
  `AcceptAnyScope` a credential could be issued a scope naming no permission. Which machine credentials a guard accepts
  is `laravel-authentication`'s replaceable `ApplicationPolicy`'s to say (`allowsMethod()`), and an application may bind
  one that reads them from somewhere other than the configuration, so the bound policy is asked for each configured
  guard, a guard whose settings it refuses (`InvalidArgumentException`) accepting nothing; only with no policy bound are
  the guard's own `application.methods`, where its `application` block holds that key, and
  `authentication.application.methods` otherwise, read. The policy is asked only when `iam:check` reads the mandate,
  never while providers register or on each boot, when the rule declares the rows: the row's mandate is a closure
  (`SeamBinding::isMandatory()`), so an application's policy is never resolved early, nor asked on every request.
  Application access is mandatory while `authorization.application_access` maps an application, since left on
  `AdmitAnyPrincipal` every principal could use it. With the map empty, the adapter and the default answer
  alike, so nothing is owed. The session policy source shares the scope registry's mandate: `NoSessionPolicy` allows
  nothing only to a principal carrying `AuthorizableMachine` and caps any other machine by nothing, so a machine whose
  credential was issued `orders.read` could do whatever its grants allow. `iam:check` refuses it whatever the switch
  says, the application's binding of it by class name included. Since `laravel-authorization` binds the seam through a
  closure that resolves the class `authorization.session.source` names, the check names a seam still holding that
  closure by that class (`MandatorySeamsCheck::holderOf()`): `NoSessionPolicy` is refused, and a class the application
  names there passes.
- Request state. None of the adapters keeps anything between calls. The subject resolver and application access are
  scoped all the same, under `iam.scoped:` (`BindingRule::bindScoped()`), so the seams themselves are never scoped, and
  the worker reset and Laravel's `forgetScopedInstances()` forget them between units of work. The caller
  `laravel-authentication` keeps on the request is dropped by the worker reset (above).
  `laravel-authorization`'s own request state, what its previews know and the console subject resolver its explanations
  resolve through included, is scoped, and the worker reset forgets it with every `authorization.default:` key; its
  explanations keep nothing beyond the check.

- The grant hook (`GrantHookAdapter`, IAM-6.7, AUTHZ-11.3). `laravel-authorization` calls it inside the grant call's
  own transaction on `authorization.connection`, with every grant of the call that widens an identity's scope, before
  it takes any lock of its own (`Hooks\WideningPhase::before()`), and never for a grant to a role. The adapter reports
  the widening to SSO first: for each distinct tenant the widening grants hold in, by the key `laravel-authorization`
  names it by once it resolves back to that tenant (`TenantTranslator::idOf()`), or `null` for a platform-wide grant,
  `ScopeWidenings::widen()`, which runs
  SSO's `widened()` in a savepoint of that transaction. Only then does it run the hooks `authorization.grant_hooks`
  lists, as `laravel-authorization`'s own composite would (`GrantHooks::fromConfig()`), so binding the adapter over the
  composite drops none of the application's. Whatever either throws refuses the grant: the call rolls back whole, the
  suspensions, deleted reservations and revoked sessions with it, and nothing is dispatched. The widening's identity
  is reported to SSO only when its type names an Eloquent model of `laravel-authentication`'s `Identity` contract
  (`IdentityReferences::namesIdentity()`), and then resolved, a row that cannot be found refusing the grant (IAM-8.2).
  Any other identity, such as an admin panel's user on a Laravel session guard, which `SubjectResolverAdapter::forUser()`
  answers as its own subject and identity, so the classifier names it as the recipient and every grant to it widens,
  is one SSO never links, so it has nothing to suspend: its widening is not reported to SSO, its tenants are not
  resolved, and only the listed hooks run, as `SubtreeGrantees` passes the same grantee over on a move. Decision this
  note records: SSO's `widened()` would take such a reference as it is, but `ScopeWidenings::widen()`, the one core
  path every widening goes through, takes `laravel-authentication`'s identity, and a widening of something SSO cannot
  hold is no widening to SSO, so the hook passes it over rather than add a second path for references.
- The lock order of a grant is SSO's first, then `laravel-authorization`'s: SSO's widening takes the identity's guard
  (`IdentityLock`), its first lock, then the identity's links and reservations in every other tenant's connections and
  the sessions established through them; `laravel-authorization` then takes its own locks and reclassifies the call
  with locking reads (`WideningPhase::assertCovers()`). A grant that widens with no hook run for it, because the
  identity's grants changed between the hook and the locks, is a conflict (`DependencyChangedException`), and the call
  is tried again from the start, hook included. Provisioning keeps the same order: the listener's grants from a group
  mapping come after SSO's link is created, so every lock of SSO's is taken before `laravel-authorization`'s, and the
  hook, called again for them, finds the identity's guard held and nothing to suspend.
- Retries. A call may run the hook more than once. Every widening of a try is written in that try's transaction and
  rolled back with it, and SSO reports a suspension only once its transaction commits, so nothing leaves a try that is
  rolled back. Inside a transaction the application opened, `laravel-authorization` never runs a try again with its
  hook: it throws `TransactionConflictException`, and the application restarts its whole transaction, since the failed
  try's row locks stay held until it ends and a hook is never called under them. SSO refuses a widening whose
  identity's links by a verified domain changed after the transaction's snapshot, before it could lock them
  (`LinkCandidatesChanged`), and the classifier's plain reads take that snapshot before the hook runs, so a link
  committed in between meets it. Decision this note records: the hook hands that refusal on as Laravel's
  `DeadlockException` with SQLSTATE `40001` and SSO's refusal as its cause, the one form `laravel-authorization`'s
  `ConflictRetries` tries a delegated call again for, and turns into `TransactionConflictException` inside the
  application's transaction. A trusted call is never tried again for a concurrency error (`OperationScope::trusted()`
  retries only its own widening conflict, and its conflict exception is the member's own), so a trusted grant outside any
  transaction reaches the caller as that `DeadlockException`; the authorization guide tells the application to make a
  trusted grant inside `Iam::transaction()`, which, as Laravel's `DB::transaction()` given attempts, tries the whole
  transaction again. While a hook runs,
  `laravel-authorization` refuses every mutation of its own (`GrantHookRecursionException`), so neither SSO's widening
  nor an application hook can grant; its read-only queries, the grant scope query among them, stay allowed.
- The hook is handed the widening as a value alone, and reads no request, current user or guard: the identity, named
  by its morph type and key, is resolved through the morph map on the write connection (`IdentityReferences`), and one
  that cannot be resolved throws `UnresolvedReferenceException`, refusing the grant rather than writing it with no
  widening reported (IAM-8.2). `laravel-authorization`'s widening carries no client, so the suspensions are reported for
  a client of which nothing is known (`new ClientContext(null, null)`), as a job's are: the contract leaves no other
  way, and the adapter's docblock says so. SSO's `widened()` refuses unless a transaction is open on SSO's storage
  connection, so a grant on a connection other than the storage connection is refused rather than written without its
  widening; the alignment of `authorization.connection` (below) keeps them one. The row is bound while the SSO
  capability's switch is on too, since it is SSO's widening that reports; with it off, `laravel-authorization`'s
  composite stays.
- A tenant crosses between the two naming schemes by one rule (`Authorization\Translation\TenantTranslator`): an id
  becomes `laravel-authorization`'s `Reference` through `laravel-authentication`'s tenant resolver, read as
  `laravel-authorization` reads a tenant (`TenantScope::extractTenantPair()`), and only when the tenant's key is exactly
  its identifier, as `laravel-authentication` records a session's tenant by its identifier and `laravel-authorization`
  keys a grant by the tenant's key; anything else throws `UnresolvedReferenceException`. A `Reference` becomes an id by
  its key only once the round trip holds: the key, resolved as an id, must name a tenant of the reference's type and
  key, or `UnresolvedReferenceException` is thrown. Taken on trust, a tenant whose key happened to be another tenant's
  identifier would be read as that other tenant: the grant hook would spare that tenant's links from suspension while
  the person reached beyond it, and the tree would place a grant where the tenant does not stand. The grant hook and
  the tree adapter both name a tenant this way, so a grant in a tenant that does not resolve back is refused, by the
  hook as the grant's tenant (`UnresolvedReferenceException::forGrantTenant()`), never as a session's. A grant to the
  identity always widens, and so does a principal's first grant in a tenant, so while the hook is bound every such grant
  in a tenant resolves its tenant: `iam:check` refuses `ResolveNoTenant` whenever the authorization and SSO adapters are
  both on (`AuthorizationSeams::reportsWidenings()`, `CrossMemberConfigurationCheck`), and whenever the authorization
  adapters are on beside a tenant tree the application names or binds, since the tree adapter resolves every tenant
  `laravel-authorization` asks about and the tree changes name the moved tenant to it, not only under SSO's enforcement
  or a tenant MFA requirement, and the installer owes the resolver for it.
- The identity directory (`IdentityDirectoryAdapter`), the grant scope (`GrantScopeAdapter`) and the tree
  (`TenantTreeAdapter`) are described with the principal scope and the tree they serve, in
  `provisioning-and-tenancy.md`: an identity's principals are those its `laravel-authentication` `principals()` relation
  lists, the model's global scopes set aside, a complete list, so the grant scope query can answer `within` and the hook
  classifies a grant by the identity's real principals, an identity that is itself a principal acting as itself alone,
  and one that is neither, whose principals only a principal resolver knows, incomplete; the grant half maps the query's
  `within`, `outside` and `unknown` onto SSO's verdicts; and `laravel-authorization`'s tree is the application's one
  tree, its own `FlatTenantTree` without one, the subtree's ids selected as text in the tree connection's grammar,
  whatever type the application's tree selects them as, every tenant of it of one type (a tree nesting two is refused
  wherever it is met), with every move the application reports beside a tree passed on to `Authorization::treeChanged()`
  while the switch is on, whatever SSO's enforcement says. A move widens the scope of everyone granted in the moved
  subtree with no grant written, so, while the grant hook is bound, the move reports each of them to SSO's scope
  widening in the moved tenant, in the move's transaction (`Authorization\SubtreeGrantees`). The group mapping and its
  re-sync (IAM-7.2) are there too, the re-sync run once the sign-in has committed.
- The permission catalogue, the administrative check and the audit access policy (IAM-6.9, IAM-6.10), and the mapping
  of `laravel-authorization`'s events to the `authorization.*` codes (IAM-9.2), are in `audit-mapping.md`.
- Forgetting the decisions that depended on authentication (IAM-6.11). `laravel-authorization` caches grant
  resolutions, never decisions: each check decides afresh on the session's proofs as they are, through the requirement
  checker (`RequirementCheck` builds a new context for every check). The one decision it keeps is the request's or the
  job's last (`Authorization::lastDecision()`, in its scoped `LastDecisionStore`), which an application's error handler
  reads to explain a refusal, and which it drops once a met requirement it read lapses (`metUntil`) or for another
  session, but not when the proofs it read change within the same request or job. So
  `Authorization\DecisionCacheInvalidation::authenticationChanged()`, the one core method, taking the identity and the
  session key as plain values, forgets the last decision when it read an authentication requirement (it carries a
  `RequirementFreshness`) and either was made in that session, compared by `laravel-authorization`'s own fingerprint
  (`Decision::isFreshFor()`), or was about that identity, by morph class and key (`DecisionProvenance::$identity`): a
  change to an identity's factors can change the requirement each of its sessions meets. A decision that read no
  requirement, or one about another identity in another session, is kept. It is called by the MFA adapters, never
  from a listener, after the member call they make succeeded:
  - `SessionRevokerAdapter::factorRemoved()`, with the sign-in MFA names (a factor removed, the session judged again,
    perhaps returned to pending);
  - `SessionRevokerAdapter::revokeAll()`, with no session (the identity's factors reset; every session ends);
  - `SessionTransitionAdapter::factorChanged()`, with the change's session (a factor confirmed, a passkey registered,
    a removal the revoker did not judge; the session kept, returned to pending or revoked);
  - `PendingCompletionAdapter::complete()`, with the pending session's key, and `StepUpAdapter::stepUp()`, with the
    session the proof is bound to (a verification passed).

  Each runs inside MFA's transaction. The last decision is forgotten at once, so a check later in the transaction reads
  the new proofs, and again should any transaction open on the storage connection roll back, since a check made between
  the change and the rollback read proofs that were never committed. The second pass is a rollback callback of every
  transaction open there that callbacks apply to (`Transactions\OpenTransactions`), not only the innermost, as
  `Audit\DeferredRefusals` waits: Laravel 12 does not tell a savepoint that has committed of its enclosing transaction's
  rollback, so MFA's transaction, a savepoint of the caller's, would otherwise leave the decision standing once the
  caller's rolls back. A commit needs no second pass: what was checked after the change read what committed. The store,
  the connection and the transactions open are resolved on every call, so the request's or the job's own store, an
  Octane sandbox's included, is the one emptied. Nothing else can be invalidated, since nothing else is kept: this is
  not a member gap.
- `laravel-authorization`'s connection (IAM-2.3). Its key is `authorization.connection` (`AUTHORIZATION_DB_CONNECTION`),
  read on every query, migration and transaction of its own (`Database\AuthorizationConnection`), not a
  `storage.connection` like the other members'. It joins `Storage\StorageConnection::MEMBER_KEYS`, and
  `Storage\ConnectionAlignment` aligns it with the others, once `laravel-authorization` has merged its configuration
  and registered: written while unset, refusing boot (and failing `StorageCheck`) while it names another connection.
  So a grant commits or rolls back with a change that spans members, SSO's scope widening finds its transaction open
  on SSO's connection, and the grant scope query reads the application's tree on the connection the tree is on.
- `authorization:prune` (IAM-2.6) is registered daily by `Scheduling\IamSchedule`, beside `mfa:prune`, as
  `laravel-authorization`'s README schedules it, whatever the capability's switch says, since its grants expire
  whether or not this package binds its seams; `SchedulesCheck` notes it when no event on the schedule runs it.
- `authorization:check` (IAM-10.1) already runs inside `iam:check` (`Checks\Checker::MEMBER_COMMANDS`). It always exits
  `0`, so it fails no run; its report reaches the output as the other members' do.
- `laravel-authorization`'s request state (IAM-11.3) is all scoped: the resolved tenant `TenantScope` reads, the
  resolution cache's memo, the last decision, the evaluator, the session scopes, the check context factory, the Gate's
  abilities, the schema its query scope reads, its previews and its manager, and every `authorization.default:` key
  (`AuthorizationServiceProvider` binds them with `scoped()`). The worker reset already forgets each of them, and the
  `Authorization` facade's root, so a later unit of work rebuilds them; the second part adds no state of its own beyond
  scoped adapters under `iam.scoped:`, which the prefix covers. Its statics (`OperationScope`'s operations, pins,
  retries and hook depth) are popped in `finally` blocks, and its `WeakMap`s are keyed by models, so nothing of them
  outlives a call.
- Resource tenants. `laravel-authorization` decides a record of another tenant as `tenant_scope` only where it knows the
  record's tenant: from a model's `QueryableResource` declaration, an `AuthorizableResource`'s own answer, or the bound
  `ResourceTenantResolver`, whose default, `NoResourceTenant`, knows none. Which tenant owns a record is the
  application's own rule (IAM-1.2), on its own models, which this package cannot read, so nothing here binds a resolver
  and `iam:install` names none. While the application has memberships (`TenancyContracts::hasMemberships()`), so its
  people act in tenants, `CrossMemberConfigurationCheck` notes, never fails, a resolver left on the default: the key
  still naming `NoResourceTenant` and the contract still bound to `laravel-authorization`'s own closure
  (`MemberDefaults::holdsDefault()`). A note, since models declaring their tenancy need no resolver, which no check can
  see.

## Success Path

1. The provider registers. The binding rule binds the ten rows over the members' defaults where the switch is on; the
   requirement checker only while `iam.adapters.mfa` is on too, the grant hook only while `iam.adapters.sso` is, and
   none of `laravel-authorization`'s rows whose class the application names in its configuration. The grant half of
   SSO's principal scope is bound to `GrantScopeAdapter`. The context's keys are queued for the key catalogue.
2. `laravel-authorization` registers, before this package or after, and binds its defaults only where nothing is bound,
   so the adapters stand.
3. `laravel-authorization` boots, reads the context's namespaces and assurance keys once every provider has registered,
   and later builds its key catalogue, with the context's keys declared on it.
4. A request on `auth:api` asks `Authorization::authorize('invoices:refund')`. The subject is the caller, with its
   session's key. A statement allowing the action states `{"authentication": {"multifactor": {}}}`; the requirement
   checker reads the session's proofs and MFA finds multifactor unmet, so `laravel-authorization` throws its
   insufficient-authentication exception.
5. Laravel turns it into a 403 HTTP exception; the mapping finds `laravel-authorization`'s exception behind it, asks MFA
   for the caller's offered factors, and renders MFA's step-up exception as the application renders it.
6. The client verifies a factor through MFA; `laravel-authentication` records the proof on the token's session. The
   next request with the same token is allowed, and another session of the same person is still refused.
7. A service account is issued an API key with the scopes `reports:read` and `reports:export`; the scope registry asks
   `laravel-authorization`'s registry about each, and both name declared permissions. Calling on an `auth:keys` route,
   it holds every report permission, but the session policy source reads the key's scopes from the guard holding it, so
   it is allowed only what those scopes cover; another account it names is allowed nothing.
8. An administrator grants a member of tenant A a role in tenant B. `laravel-authorization` opens the call's
   transaction on the storage connection and calls the grant hook with the widening; SSO suspends the member's link by
   A's verified domain and revokes the sessions it established, and the role is written. Both commit together, and the
   role's assignment is recorded as `authorization.role_assigned`. Had an application hook listed in
   `authorization.grant_hooks` refused, nothing would have been written or suspended.
9. The member removes a factor in a request that has already checked an action guarded by an authentication
   requirement. MFA's removal reaches `SessionRevokerAdapter::factorRemoved()`, which forgets that last decision, so
   the request's error handler never explains a later refusal by an allow the session's proofs no longer support.

## Failure / Edge Cases

- A subject with no session never reaches the checker: `laravel-authorization` finds every part of the requirement
  unmet without asking it (`RequirementCheck::resultOf()`), so neither an allow nor a deny the requirement guards
  applies. A deny guarded by a requirement never refuses a machine on an API key or a client-credentials token, a
  principal named through `Authorization::for()` or `Gate::forUser()`, or a queued job. The checker still refuses such
  a subject by throwing, should anything else ask.
- The authentication context (`AuthenticationContextAdapter::values()`) is always the request's own caller's
  (`AuthenticationContexts::current()`, the default guard's), never the subject a check names: its contract takes
  nothing, and `laravel-authorization` builds every check's `authentication`, `mfa` and `sso` namespaces from that one
  source, whoever the check is about. So the guide tells an application to refuse the caller's own sessionless checks
  (a machine on its key or token, and a queued job, whose context is empty) by a condition on
  `authentication.credential` or `authentication.session_id`, or to cap a machine by its credential's scopes, and says
  plainly that no such condition refuses a check about a named principal while the caller holds a session: the deny
  reads the caller's session, not the named principal's. Such a check can be refused only by not naming principals for
  an action a requirement guards, by the application's own code, or by a condition on a `subject.*` attribute
  (`SessionlessDenyTest`).
- A subject with no guard, an identity MFA cannot hold factors for, a guard that holds no sessions, a key naming no
  session of the identity's, a principal acting for another identity, any other subject that is not the identity whose
  session it names, a session in another tenant, a tenant that cannot be read, and a level MFA does not know are each
  refused by throwing, which `laravel-authorization` reads as undecidable: an allow the requirement guards does not
  apply, and a deny it guards does.
- `forUser()` with an identity that is neither the caller's nor a principal answers it as its own subject, in no tenant
  and with no session, so a decision about it counts only the grants made to it, and a grant made to it reaches the
  grant hook as a grant to the identity.
- A session's reauthentication at its provider meets a requirement's maximum age in the checker as at MFA's route gate,
  where the application's combination policy trusts the connection and SSO accepted the evidence; with the evidence
  unaccepted, or the session's tenant not trusting the connection, MFA sees the proof name no connection, in both.
- An application that binds its own authentication context declares its own keys; none of this package's is declared.
- An application whose exception handler is not Laravel's maps `laravel-authorization`'s exception itself; a render
  callback the application registers first for the same HTTP exception answers before this one.
- A machine principal is admitted on an application `authorization.application_access` maps on its grants, as a
  person is: an admission holds no credential whose scopes could cap it, so neither a credential's scopes nor a
  machine's missing ones refuse it, while a deny, a boundary or a guardrail still does. An application the map leaves
  out is open to every principal, a person with no grant included.
- A subject that is not a principal, paired with another identity's session, and a session acting in a tenant other
  than the subject's, are refused by throwing, so another identity's proofs never meet a requirement for the subject.
- A refusal about a subject the caller names, decided on no session, or one decided on another session, or carrying no
  decision, is not mapped: it stays Laravel's 403.
- An application policy of the application's own that lets a guard accept `api_key` or `client_credentials` makes the
  scope registry mandatory, whatever the guard's configured methods list.
- A key issued a scope `laravel-authorization`'s registry does not accept is refused before anything is written, and a
  rotation holds the scopes to the registry again; a guard the subject names that is not configured throws, and
  `laravel-authorization` makes no decision.
- Gaps in the members the adapters work around:
  - `laravel-authorization` recognises a machine only by its own marker (`AuthorizableMachine`): a session policy
    source answering `null` allows such a subject nothing, and caps any other by nothing, though
    `laravel-authentication` marks its machines `MachineIdentity`. The adapter answers a machine `[]` itself; with the
    switch off, `NoSessionPolicy` uncaps an unmarked machine, which is why `iam:check` refuses it while a guard accepts
    a machine credential. Recognising `laravel-authentication`'s machine contract, or failing closed for any subject
    whose source answers nothing, would close it.
  - `laravel-authentication` keeps `Auth::caller()` on the request's attributes for the rest of the request, and its own
    reset between queued jobs (`ForgetGuardStateBeforeJob`) resets the guards but not that memo, so a worker's later
    jobs would read the first job's caller. The worker reset drops it; a reset of its own memo beside the guards' would
    close it.
  - `laravel-authentication`'s caller carries no credential scopes (they live on `ContextualGuard::scopes()` alone), which
    forces the session policy source's ambient read. Scopes on `Caller`, filled as the access credential is admitted,
    would let the subject carry them and the source take them as a plain value.
  - `laravel-mfa` builds its step-up exception only in its middleware, and the confirmed-factor read it uses
    (`ConfirmedFactors`) is `@internal`, so the mapping derives whether a confirmed factor is held from `Mfa::factors()`.
    A public factory for the step-up exception from a caller and a requirement would close it.
  - `laravel-authorization` keeps the request's last decision (`LastDecisionStore`) past a change to the proofs it
    read, until its requirement's `metUntil` passes, and offers no way to forget the decisions of one session or
    identity, only `forgetLastDecision()`. `DecisionCacheInvalidation` forgets it through the store, judged by its
    `RequirementFreshness` and its provenance (above). A `sessionChanged()` of its own, or dropping the last decision
    whose session's proofs changed, would close it.
  - `laravel-authorization`'s `authorization:prune` names its command in its signature alone, with no constant to
    schedule it by, so `IamSchedule::AUTHORIZATION_PRUNE` spells it; and `authorization:check` reports only its Gate
    hook and always exits `0`, so `iam:check` runs it for its report and fails on nothing it says.
  - `laravel-authorization` binds its resource tenant resolver through one closure its provider declares, whatever
    class `authorization.resource_tenant_resolver` names, so the binding alone cannot tell the application's resolver
    from `NoResourceTenant`; the check reads the configuration beside it (above).
  - `laravel-authorization`'s grant widening (`Hooks\GrantWidening`) carries no client, so the suspensions and
    revocations a grant causes are reported to SSO for a client of which nothing is known. Carrying the operation's
    client (its IP address and user agent) on `Support\Operation` and the widening would close it.
  - `laravel-authorization` names a tenant by its morph type and key (`Support\Reference`), never by
    `laravel-authentication`'s identifier, so the package equates the key with the identifier
    (`TenantTranslator`), refusing a tenant keyed otherwise wherever it names one, the grant hook and the tree
    included. Letting
    `AuthorizableTenant` name its identifier, or documenting the equivalence, would close it.
  - `laravel-authorization`'s default identity directory (`GuardUserIdentityDirectory`) is complete only under its own
    subject resolver, so under any other its grant scope query never answers `within` and every grant to an identity
    is classified as widening. `IdentityDirectoryAdapter` answers it; the README naming the umbrella's adapter would
    say so.
  - `laravel-authorization` has no query for the tenants where a subject holds an action, so the audit access policy
    lists the viewer's actions in the tenants its memberships name, and a grant in any other tenant, or reached only
    through a subtree, is not seen (`audit-mapping.md`). A read-only query naming those tenants would close it.
  - `laravel-authorization`'s `for(Subject)` decides in the request's resolved tenant whatever tenant the subject
    names, so `AdministrativeCheck` puts the subject's own scope in place for the check
    (`AuthorizationScope::within()`). Deciding a named subject in its own tenant and application would close it.
  - `laravel-authorization` dispatches `DecisionEvaluated` for every check, allows included (its BL-72), so the mapper
    filters denials itself; and a decision's `usedBreakGlass` is always `false` until break-glass grants exist (its
    BL-70), so `authorization.break_glass_used` is defined and mapped but never recorded (`audit-mapping.md`).

## Departures from the Plan

The M11 File Change Manifest is followed for part (a), with these departures:

- The authentication context adapter is `Authorization\AuthenticationContextAdapter`, not the manifest's
  `AuthenticationContextSourceAdapter`: it is named after the contract `laravel-authorization` shipped,
  `Contracts\AuthenticationContext`, which the plan, written before the seam existed, marked unverified and named a
  context source.
- Three units the manifest does not list are split out. `Authorization\AccessMandates` holds the predicates that make
  the scope registry and application access mandatory, read by the binding rule as it declares the rows and by
  `iam:check` as it runs, so the two read one rule. `Authorization\AuthenticationContextKeys` declares the context's
  keys on `laravel-authorization`'s key catalogue, which its contract requires of an application supplying a namespace,
  and which no adapter could do as it answers. `Authorization\Translation\RequirementTranslator` crosses a requirement
  from `laravel-authorization`'s terms to MFA's and back, shared by the requirement checker and the step-up mapping,
  each of which would otherwise translate alone; its unit test sits beside it.
- The binding rule's own units change (`Bindings\BindingRule`, `Bindings\SeamBinding`), since a row over
  `laravel-authorization` keeps a class the application names in its configuration, which the manifest, expecting its
  resolvers to be named in configuration, did not foresee. For the same reason `iam:install` writes none of
  `laravel-authorization`'s resolver keys and `CrossMemberConfigurationCheck` requires none (`install-and-check.md`).

Part (b) follows the manifest's remaining rows, with these departures:

- `Authorization\IdentityDirectoryAdapter`, which neither the plan nor the manifest names, answers
  `laravel-authorization`'s identity directory from `laravel-authentication`'s principals. Without it the grant scope
  query never answers `within` under this package's subject resolver, so SSO would link nobody by a verified domain
  (IAM-6.8), and every grant to an identity would be reported as widening for want of the list (IAM-6.7). The
  principals are the subjects under the suite, so their list is the complete answer, with no change to the
  application's memberships (`Membership` names no principal) or provisioner (`createMembership()` still answers
  nothing). Its tests are in `GrantScopeAdapterTest`.
- `Tenancy\Contracts\GrantScope` is bound by `IamServiceProvider::registerSeams()`, `bindIf()` to the adapter while the
  switch is on and `singletonIf()` to `UnknownGrantScope` while it is off, not by a `TenancySeams` row: it is this
  package's own port, not a member's seam, so a row would bring it into `iam:check`'s mandatory seams and the
  apply-again machinery for nothing. No method is added to the provider.
- `Authorization\Translation\TenantTranslator`, which the manifest does not list, crosses a tenant between the two
  naming schemes for the grant hook, the grant scope, the tree changes, the administrative check and the audit access
  policy, as `RequirementCheckerAdapter` already equates them; no new application contract is needed.
- The grant hook is bound over `laravel-authorization`'s composite whatever hooks it lists, and runs them after SSO's
  widening, rather than being listed in `authorization.grant_hooks` by `iam:install`: the application's own list is
  kept, and the binding follows the same rule as every other row.
- The tree's row is bound whenever the switch is on, through a factory (`SeamBinding::$factory`, which the manifest does
  not list) that builds the adapter while the application names or binds a tree and `laravel-authorization`'s own
  `FlatTenantTree` otherwise, decided as each request or job first resolves the scoped seam, rather than a row that
  applies only while the application has a tree: the reserve and apply-again machinery of the SSO tenancy rows is not
  needed, and a tree bound after the providers register (a test's `FakeTenantTree::fake()`) is read from the next unit
  of work. `laravel-authorization` tells a flat application by the
  class of the tree bound, so an adapter answering as a flat tree took a flat application down the hierarchical paths,
  and `whereAuthorized()` refused a model on another connection than the storage connection (`subtree_connection`).
  `Iam::treeChanges()->changed()` reports to `laravel-authorization` beside a tree, whatever SSO's enforcement says, and
  `iam:check` makes the tenant resolver mandatory there.
- The subtree selects each id as text (`CAST(... AS CHAR)` on MySQL and MariaDB, `TEXT` on SQLite, `VARCHAR` on
  PostgreSQL and elsewhere) rather than as the application's tree selects it: `laravel-authorization` compares it with
  its own text `tenant_id` columns, which PostgreSQL refuses for an integer column, so the grant scope query answered
  `unknown` for everyone under a tree over integer keys. `Contracts\TenantTree` is unchanged.
- A move reports every identity holding a live grant rooted in the moved subtree to SSO's scope widening, in the moved
  tenant, while the grant hook is bound (`Authorization\SubtreeGrantees`, which the manifest does not list, reading
  `laravel-authorization`'s grant tables on its connection): the grant half counts a grant below a tenant within it, so
  a move out from under a linked tenant widens the person's scope with no grant written, and no grant hook runs. The
  package sees only where a tenant ends up, so this is broader than needed, never narrower: a link in a tenant the
  subtree still stands below is suspended too, latched, and is linked again. A boundary only narrows, and a grant to a
  role widens nobody, so neither is read. Every grantee's identity guard is taken first, in SSO's order, ascending by
  SSO's digest, before any widening locks a connection (`Sso\IdentityGuards`, which the manifest does not list either):
  SSO's widening reports one identity, its guard then its connections, so one widening after another would take a guard
  after a connection and deadlock with a grant, reservation or activation of a later grantee holding its guard and
  waiting for that connection. SSO offers neither a widening of several identities nor a public way to take the guard,
  so this reaches SSO's internal `Linking\IdentityLock` (`acquire()`, `digest()`); each widening then takes its guard
  again, held already, and waits for nothing.
- The group re-sync runs once the sign-in's transaction has committed, in a transaction of its own, rather than inside
  it: a re-synced grant that widens reports to SSO's scope widening, which takes the identity's guard, and SSO's lock
  order puts the guard before every connection, which the redemption had already locked, so the re-sync under its locks
  deadlocked with a grant or a link of the same person. The credential leaves only once the re-sync has committed; a
  re-sync that refuses leaves the code spent and the session written, never handed out.
- A `GrantInstruction` is a role and whether it reaches the tenants below, granted to the new identity in the
  connection's tenant, never the plan's `(role, ?tenantId)`: a connection's groups are only as trustworthy as the
  connection, so they never grant beyond its tenant. `Provisioning\GroupSettings`, `Provisioning\GroupGrants`,
  `Provisioning\MappedGroupResync` and `Exceptions\GroupMappingMisconfiguredException`, which the manifest does not
  list, find the mapping, make the grants, ship the re-sync an application may name, and refuse a mapping
  misconfigured (`provisioning-and-tenancy.md`).
- `tests/Integration/Authorization/GrantWideningTransactionTest.php` is not created: provisioning with groups in one
  transaction is `tests/Integration/EndToEnd/GroupGrantsThroughSsoTest.php`, and a refusal rolling the grant and the
  widening back, inside `laravel-authorization`'s transaction and inside the application's, is
  `GrantHookAdapterTest`. The retries are `laravel-authorization`'s own, proved by its suite, and provisioning is
  attempted once. The provisioning and re-sync rows of `ProvisionOnUnlinkedResultTest` and `SignInRedemptionTest` are
  that end-to-end test too, and the tree change row of `TreeChangesTest` is `TenantTreeAdapterTest`.
- The audit access policy is a row of `AuthorizationSeams` over audit-log's `DenyAllPolicy`, shared and never
  mandatory. The mapper's codes are `Audit\Enums\AuthorizationActivity`, as `audit-mapping.md` fixed, with four codes
  beyond IAM-9.2's list and the role sequence in `tests/Integration/Audit/AuthorizationRecordsTest.php` rather than
  `RecordSequencesTest`; the administrative operations are `Authorization\Enums\AdministrativeOperation`, and the
  check takes the subject as a plain value, which the plan's signature did not (`audit-mapping.md`).

- `Authorization\DecisionCacheInvalidation` forgets `laravel-authorization`'s last decision, the one decision it keeps,
  rather than invalidating a decision cache: `laravel-authorization` has none (above). Its tests are
  `tests/Feature/Authorization/DecisionCacheInvalidationTest.php`, for the rule, and the manifest's integration test,
  through MFA's real removal and step-up; each MFA adapter's own test shows it calls it, the step-up adapter's
  included (`StepUpAdapterTest`).
- `src/Console/CheckCommand.php` is unchanged: `authorization:check` already ran inside `iam:check`
  (`Checker::MEMBER_COMMANDS`); its test now binds a tenant resolver, which the grant hook makes mandatory.
  `src/Workers/WorkerReset.php` changes only its docblock, which names the tenant tree among the scoped instances it
  forgets; its behaviour and its test are unchanged: part (a) already forgets every scoped instance
  `laravel-authorization` keeps, and there is no `TenantScope` state of its own to reset.
- No resource tenant resolver is named by `iam:install` (the last row of part (a)'s waiting list, named in neither the
  plan nor FEATURES): a record's tenant is the application's to say, and a configured class cannot be told from the
  default by its binding. `CrossMemberConfigurationCheck` notes the default instead, while people act in tenants.
- A tenant tree must hold tenants of one type (`TenantTreeAdapter`, `provisioning-and-tenancy.md`), which neither the
  plan nor IAM-7.5 says: the application's tree selects ids alone, so the subtree `laravel-authorization` nests names
  every tenant by the type of the tenant asked about. A tree nesting two types is refused with
  `TenancyMisconfiguredException` where the package meets it (`ancestors()`, `TenantTreeAdapter::tenantsIn()`, which
  confirms the grant half's `outside` and lists a move's grantees), rather than have the grant scope query read a
  grant below a tenant as one beyond it. `iam:check` cannot tell such a tree: the tree contract lists no tenants without
  one to start from. `Transactions\OpenTransactions`, which the manifest does not list, holds the transactions a
  rollback callback must wait on, shared by `Audit\DeferredRefusals` and `DecisionCacheInvalidation`.
- IAM-13.7 (decision Q15) is stale on every count at the commit this package requires: the resolvers are bound with
  `bindIf()` over scoped keys rather than a plain `singleton()`, so they give way to anything bound before or after,
  change events fire after commit, the connection setting exists, the authentication context is a contract, and the
  resource tenant resolver is consulted by the decision path (a resource of another tenant is denied as
  `tenant_scope`). FEATURES is not edited here.

## Implementation Anchors

- `src/Authorization/AuthorizationSeams.php`: `seams()`, `isOn()`, `reportsWidenings()`, `authorizationRow()`,
  `SWITCH`, `DOMAIN_LINKING`; `src/IamServiceProvider.php`: `seamProviders()`; `config/iam.php`:
  `adapters.authorization`.
- `src/Bindings/SeamBinding.php`: `$configurationKey`, `$factory`, `configuredClass()`, `namesApplicationClass()`,
  `isMandatory()`; `src/Bindings/MemberDefaults.php`: `isReplaceable()`, `holdsDefault()`;
  `src/Bindings/BindingRule.php`: `apply()`; `src/Checks/MandatorySeamsCheck.php`: `holderOf()`.
- `src/Authorization/SubjectResolverAdapter.php`: `resolve()`, `forUser()`.
- `src/Authorization/AuthenticationContextAdapter.php`: `namespaces()`, `assuranceKeys()`, `values()`, `NAMESPACES`,
  `ASSURANCE_KEYS`;
  `src/Authorization/AuthenticationContextKeys.php`: `register()`, `declareOn()`, `KEYS`.
- `src/Authorization/RequirementCheckerAdapter.php`: `check()`, `identityOf()`, `inTenantOf()`, `tenantOf()`,
  `FURTHER_KINDS`;
  `src/Authorization/Translation/RequirementTranslator.php`: `toMfa()`, `result()`;
  `src/Mfa/RequirementCheckAdapter.php`: `since()`; `src/Mfa/CurrentSession.php`: `named()`,
  `sessions()`; `src/Mfa/SignInProofs.php`: `of()`.
- `src/Authorization/InsufficientAuthenticationMapping.php`: `register()`, `stepUp()`, `isDecidedOn()`.
- `src/Authorization/SessionPolicySourceAdapter.php`: `scopesFor()`; `src/Authorization/ScopeRegistryAdapter.php`:
  `rejected()`; `src/Authorization/ApplicationAccessAdapter.php`: `mayUse()`; `src/Authorization/AccessMandates.php`:
  `acceptsMachineCredentials()`, `isMachineGuard()`, `namesApplicationAccess()`, `MACHINE_METHODS`,
  `APPLICATION_ACCESS`.
- `src/Workers/WorkerReset.php`: `reset()`, `forgetMemberState()`, `forgetCallers()`.
- `src/Authorization/GrantHookAdapter.php`: `beforeWidening()`; `src/Authorization/Translation/TenantTranslator.php`:
  `toReference()`, `idOf()`; `src/Authorization/IdentityDirectoryAdapter.php`: `principalsOf()`;
  `src/Authorization/GrantScopeAdapter.php`: `judge()`, `outside()`; `src/Authorization/TenantTreeAdapter.php`:
  `ancestors()`, `isWithin()`, `subtree()`, `tenantsIn()`, `forApplication()`;
  `src/Exceptions/TenancyMisconfiguredException.php`: `forMixedTree()`; `src/Authorization/SubtreeGrantees.php`: `of()`;
  `src/Sso/IdentityGuards.php`: `acquire()`; `src/Tenancy/TreeChanges.php`: `changed()`, `reportToAuthorization()`;
  `src/Bindings/SeamBinding.php`: `$factory`;
  `src/Sso/SignInRedemption.php`: `redeem()`, `resync()`; `src/IamServiceProvider.php`:
  `registerSeams()`; `src/Tenancy/ScopeWidenings.php`: `widen()`.
- `src/Authorization/AuditAccessPolicyAdapter.php`: `scope()`; `src/Authorization/PermissionCatalogue.php`:
  `permissions()`; `src/Authorization/AdministrativeCheck.php`: `authorize()`;
  `src/Audit/Mappers/AuthorizationEventMapper.php`: `map()`.
- `src/Authorization/DecisionCacheInvalidation.php`: `authenticationChanged()`, `forget()`, `isAbout()`;
  `src/Transactions/OpenTransactions.php`: `manager()`, `on()`;
  `src/Mfa/SessionRevokerAdapter.php`: `factorRemoved()`, `revokeAll()`; `src/Mfa/SessionTransitionAdapter.php`:
  `factorChanged()`; `src/Mfa/PendingCompletionAdapter.php`: `complete()`; `src/Mfa/StepUpAdapter.php`: `stepUp()`.
- `src/Storage/StorageConnection.php`: `MEMBER_KEYS`; `src/Storage/ConnectionAlignment.php`: `align()`,
  `assertAligned()`, `assertRegistered()`, `MEMBER_PROVIDERS`.
- `src/Scheduling/IamSchedule.php`: `register()`, `AUTHORIZATION_PRUNE`; `src/Checks/SchedulesCheck.php`: `checks()`;
  `src/Checks/Checker.php`: `MEMBER_COMMANDS`.
- `src/Checks/CrossMemberConfigurationCheck.php`: `checks()`, `resourceTenantsNote()`.

## Authoritative Tests

- `tests/Feature/Authorization/AuthorizationSeamsTest.php`
  `testEveryAdapterIsBoundOverItsMembersDefaultInEveryProviderOrder`,
  `testAClassTheApplicationNamesInAuthorizationsConfigurationIsKept`,
  `testAnApplicationBindingMadeOnceEveryProviderHasRegisteredWins`, `testTheSwitchOffBindsNothing`,
  `testTheRequirementCheckerFollowsTheMfaSwitch`,
  `testEachRowReadsLaravelAuthorizationsConfigurationKeyAndOnlyTheResolverIsScoped`,
  `testTheSubjectResolverIsOneForAUnitOfWork`,
  `testRebindingTheResolverOrTheTreeForgetsResolutionsInEveryProviderOrder`,
  `testTheSwitchIsReadLeniently`, `testTheContextsKeysAreDeclared`, `testAKeyTheApplicationDeclaresKeepsItsDeclaration`,
  `testNoKeyIsDeclaredForAnApplicationsOwnContext`, `testTheContextsAssuranceKeysAreUntestableUnderEveryNamespace`,
  `testAnAuthorizationRegisteredWhileBootingLeavesEveryAdapterBound`,
  `testWhatIsResolvedWhileBootingIsBuiltWithTheAdapters`,
  `testAnApplicationBindingMadeBeforeAuthorizationRegistersAfterThisPackageIsKept`,
  `testAnAuthorizationRegisteredAgainLeavesEveryAdapterBound`
- `tests/Feature/Authorization/AccessSeamsTest.php` `testEveryAdapterIsBoundOverItsMembersDefaultInEveryProviderOrder`,
  `testASourceTheApplicationNamesInAuthorizationsConfigurationIsKept`,
  `testTheAccessSeamsAreMandatoryWhileTheConfigurationSaysSo`, `testIamCheckRefusesTheDefaultSourceWithTheSwitchOff`,
  `testIamCheckRefusesTheDefaultSourceTheApplicationBindsByName`,
  `testIamCheckPassesASourceTheApplicationNamesInAuthorizationsConfiguration`,
  `testIamCheckAsksTheBoundApplicationPolicyWhichMachineCredentialsAGuardAccepts`,
  `testTheApplicationPolicyIsAskedOnlyWhenTheMandateIsRead`
- `tests/Unit/Bindings/MemberDefaultsTest.php` `testADefaultClassBoundByNameIsNoMembersOwnBinding`,
  `testAClosureNoMemberDefaultDeclaresIsNoMembersOwnBinding`
- `tests/Feature/Bindings/BindingRuleTest.php` `testARowWhoseConfigurationNamesAnotherClassIsKept`
- `tests/Integration/Authorization/SubjectResolverAdapterTest.php` (every isolation level where it signs in)
  `testTheRequestsCallerIsTheSubject`, `testACallerWithoutASessionIsTheSubjectWithNone`,
  `testTheGuardsOwnPrincipalIsTheCallerWithItsSession`, `testACopyOfTheCallerLoadedAgainIsTheCaller`,
  `testAnyOtherPrincipalHasNoSession`, `testEachJobInAWorkerIsDecidedAboutItsOwnCaller`,
  `testAnIdentityThatIsNoPrincipalAndAnyOtherModelAreTheirOwnSubject`,
  `testAnotherKindOfGuardIsAnsweredAsLaravelAuthorizationsOwn`,
  `testAPrincipalKeepsItsIdentityAndTenantWhicheverGuardIsTheDefault`
- `tests/Integration/Authorization/IdentityGranteeTest.php` (every isolation level)
  `testAGrantToAnIdentityThatIsNoPrincipalIsWrittenAndDecided`
- `tests/Unit/Authorization/SubjectResolverAdapterTest.php` `testACallerStillChoosingItsPrincipalIsNoSubject`,
  `testASessionKeyedByAnIntegerIsNamedAsText`, `testACopyOfTheCallersIdentityLoadedAgainIsTheCaller`,
  `testACopyOfTheCallersPrincipalLoadedAgainIsTheCaller`,
  `testAnotherKindOfGuardsPrincipalActsForItsIdentityInItsTenant`
- `tests/Integration/Authorization/AuthenticationContextAdapterTest.php` `testTheNamespacesAreFixed`,
  `testTheValuesAreTheRequestsContext`, `testANamespaceAnotherContributorAddsIsNotSupplied`
- `tests/Integration/Authorization/RequirementCheckerAdapterTest.php` (MySQL and PostgreSQL at READ COMMITTED and
  REPEATABLE READ) `testARequirementIsUnmetUntilTheSessionStepsUp`, `testAMaximumAgeBoundsTheAnswer`,
  `testEachPartIsJudgedAsMfaJudgesIt`, `testOnlyTheSubjectsOwnSessionIsJudged`, `testASessionNoLongerLiveMeetsNothing`,
  `testAnInactiveIdentityMeetsNoRequirement`,
  `testASubjectPairedWithAnotherIdentitysSessionIsRefused`, `testTheSessionMustActInTheSubjectsTenant`,
  `testATenantInLaravelAuthorizationsTermsIsReadByItsKey`,
  `testWhatCannotBeResolvedOrJudgedIsRefused`, `testAPrincipalIsJudgedOnTheIdentityItActsFor`,
  `testTheProofsReachMfaAfterTheFirstFactorOldestFirst`, `testInsideATransactionTheProofsAreReadCurrent`
- `tests/Integration/Authorization/RequirementGuardedDenyTest.php` (every isolation level)
  `testADenyAppliesOnlyWhereItsRequirementIsUndecidable`
- `tests/Integration/Authorization/SessionlessDenyTest.php` (every isolation level)
  `testADenyOnTheContextsSessionRefusesOnlyTheCallersOwnSessionlessChecks`
- `tests/Integration/Authorization/ProviderReauthenticationTest.php` (every isolation level)
  `testAReauthenticationAtTheProviderMeetsAMaximumAgeInTheGateAndTheChecker`
- `tests/Integration/Authorization/SubjectResolutionMemoTest.php` (every isolation level)
  `testChecksAskedAgainInOneRequestAreAnsweredFromTheMemo`
- `tests/Unit/Authorization/Translation/RequirementTranslatorTest.php` `testEachPartCrossesWithItsMaximumAge`,
  `testALevelMfaCannotRequireIsRefused`, `testTheEvaluationCrossesBack`
- `tests/Feature/Authorization/InsufficientAuthenticationMappingTest.php`
  `testTheFirstRequirementMfaCanExpressIsAskedFor`, `testOnlyARefusalDecidedOnTheCallersSessionAsksForAStepUp`,
  `testARefusalAboutANamedSubjectStaysLaravels403`, `testARefusalWithNoSubjectStaysLaravels403`,
  `testARefusalIsRenderedAsMfasStepUp`, `testWhatIsNotMappedIsRenderedAsLaravelRendersIt`,
  `testTheMappingIsRegisteredOnLaravelsHandlerWheneverItIsResolved`,
  `testTheMappingFollowsTheSwitchesAsTheBindingRuleReadThem`
- `tests/Integration/EndToEnd/StepUpAuthorizationTest.php` (every isolation level)
  `testARequirementDeniesUntilTheSessionStepsUpThroughMfa`, `testARefusalAboutANamedMemberIsNoStepUp`,
  `testAMemberWithNoConfirmedFactorIsToldItHoldsNone`, `testARequirementMfaCannotJudgeIsUndecidable`,
  `testAListingInTheCallersTenantDecidesAsTheCheckDoes`
- `tests/Integration/EndToEnd/MachineScopesTest.php` (the first two at every isolation level)
  `testAKeysScopesBoundWhatItsAccountMayDo`, `testAMappedScopeCoversWhatItStandsForAndGrantsNothing`,
  `testAMachineWithoutAuthorizationsMarkerIsAllowedNothingWhereNoCredentialCapsIt`,
  `testAKeyIsNeverIssuedAScopeNamingNoPermission`
- `tests/Feature/Authorization/AccessSeamsTest.php` `testAnApplicationBindingOfAuthenticationsContractsMadeFirstIsKept`,
  `testTheSourceAndTheRegistryAreTransientAndApplicationAccessScoped`, `testApplicationAccessIsForgottenBetweenUnitsOfWork`,
  `testIamCheckRefusesTheDefaultsWhileTheyAreMandatory`
- `tests/Unit/Authorization/AccessMandatesTest.php`
  `testTheScopeRegistryIsMandatoryWhileAGuardAcceptsAMachineCredential`,
  `testApplicationAccessIsMandatoryWhileAnApplicationIsMapped`,
  `testTheBoundApplicationPolicySaysWhichMachineCredentialsAGuardAccepts`
- `tests/Unit/Authorization/SessionPolicySourceAdapterTest.php` `testTheScopesAreAnsweredOnlyForTheSessionTheGuardHolds`,
  `testASubjectNamingNoGuardReadsNoGuard`, `testAGuardHoldingNoPrincipalAnswersNoCap`,
  `testAGuardThatHasNotResolvedItsRequestIsNeverEntered`, `testAMachineTheGuardDoesNotHoldIsAllowedNothing`,
  `testAMachineNamingNoGuardIsAllowedNothing`, `testAPrincipalActingForAPersonIsAnsweredNoCap`
- `tests/Integration/Authorization/SessionPolicySourceAdapterTest.php` `testAnApiKeyCapsItsAccountByItsScopes`,
  `testAMachineTheGuardDoesNotHoldIsAllowedNothing`, `testAMachineNamingASessionTheGuardDoesNotHoldIsAllowedNothing`,
  `testAPersonsSessionCapsNothing`, `testAGuardThatIsNotContextualCarriesNoCap`,
  `testAGuardThatIsNotConfiguredIsRefused`, `testAGuardThatHasNotResolvedItsRequestIsNotResolvedForTheSource`
- `tests/Integration/Authorization/ScopeRegistryAdapterTest.php` `testAKeyWithAScopeNamingNoPermissionIsRefused`,
  `testTheRegistryRejectsEachScopeAuthorizationDoesNotAccept`, `testTheApplicationsOwnAuthorizationRegistryIsAsked`,
  `testARotationHoldsTheScopesToTheRegistryAgain`
- `tests/Integration/Authorization/ApplicationAccessAdapterTest.php` (the grants read from the primary, inside
  `WriteConnection::during()`; the withdrawn grant commits before the refresh asks, so no read mode is at stake)
  `testAMemberSignsInOnlyWithThePermissionToUseTheApplication`, `testAGrantForAnotherApplicationDoesNotCount`,
  `testAnApplicationTheMapDoesNotNameAdmitsEveryone`, `testAWithdrawnGrantRefusesTheNextRefresh`,
  `testAPrincipalIsAdmittedOnItsIdentitysGrantWhicheverGuardIsTheDefault`,
  `testAMachineIsAdmittedOnAnApplicationTheMapNamesOnItsGrants`
- `tests/Unit/Workers/WorkerResetTest.php` `testResetForgetsTheMembersScopedState`,
  `testResetForgetsThePackagesScopedAdapters`, `testForgettingTheMemberStateDropsTheRequestsCallers`
- `tests/Feature/Authorization/GrantSeamsTest.php` `testEveryAdapterIsBoundOverItsMembersDefaultInEveryProviderOrder`,
  `testTheGrantHookIsBoundWhateverHooksAreListed`, `testAClassTheApplicationNamesInAuthorizationsConfigurationIsKept`,
  `testAnApplicationBindingWins`, `testWithTheSsoSwitchOffTheGrantHookIsLeftAlone`,
  `testWithTheSwitchOffNothingIsBound`, `testTheGrantHookIsMandatoryWhileDomainLinkingIsOn`,
  `testIamCheckRefusesTheCompositeWhileDomainLinkingIsOn`, `testTheTreeIsOneForAUnitOfWork`,
  `testWithoutATreeTheMembersFlatTreeIsTheSeam`,
  `testGrantsAreReportedToSsoOnlyWhileBothSwitchesAreOn`,
  `testAnIdentityOfAnotherKindIsPassedOverAndTheListedHooksRun`
- `tests/Integration/Authorization/GrantHookAdapterTest.php` (every isolation level)
  `testAGrantInATenantSuspendsTheLinkInAnotherTenantAndRevokesItsSessions`, `testAPlatformGrantSuspendsTheLink`,
  `testAGrantInTheLinksOwnTenantLeavesItAlone`, `testEveryTenantTheWideningGrantsHoldInIsReported`,
  `testAHookTheApplicationListsStillRunsAfterTheWidening`, `testARefusalAfterTheWideningRollsEverythingBack`,
  `testAGrantInsideTheApplicationsTransactionRollsBackWithIt`,
  `testAGrantWhoseLinkCandidatesChangedIsTriedAgainWithItsTransaction`,
  `testAGrantToAGranteeThatIsNoIdentityIsWrittenAndItsHooksRun`;
  `testAGrantInATenantThatDoesNotResolveBackIsRefused`, `testAGrantInATenantUnderTheDefaultResolverIsRefusedAsTheGrants`,
  `testLinkCandidatesThatChangedAreAConcurrencyError`, `testAWideningOfAnIdentityThatCannotBeFoundIsRefused`
- `tests/Integration/Authorization/GrantScopeAdapterTest.php` (every isolation level) `testAPersonIsPlacedByTheirGrants`,
  `testAPersonIsPlacedByTheirPrincipalsGrants`, `testTheJudgementReadsInsideTheCallersTransaction`,
  `testATenantKeyedOtherwiseThanItsIdentifierThrows`, `testAnIdentityTheDirectoryCannotResolveIsIncomplete`,
  `testATreeOfIntegerIdsPlacesAGrantInTheTenantWithinIt`; `testAPrincipalAGlobalScopeHidesStillPlacesItsPerson`,
  `testAnIdentityWhosePrincipalsCannotBeListedIsUnknown`, `testAGrantBelowTheTenantInATenantOfAnotherTypeIsRefused`
- `tests/Integration/Authorization/TenantTreeAdapterTest.php` (every isolation level) `testItAnswersTheApplicationsTree`,
  `testTheSubtreeSelectsEachTenantsTypeAndId`, `testWithoutATreeARecordOnAnotherConnectionIsScopedByItsTenant`,
  `testAReportedMoveReachesAuthorization`, `testWithTheSwitchOffNothingIsReportedToAuthorization`;
  `testACheckReadsTheTreeOncePerUnitOfWork`, `testTheSubtreeSelectsEachIdAsText`, `testAskedWithNoTreeTheAdapterRefuses`,
  `testWithoutATreeNothingIsReportedToAuthorization`, `testTheSubtreesTenantsAreListed`,
  `testATreeNestingTwoTenantTypesIsRefused`
- `tests/Integration/Authorization/TreeMoveWideningTest.php` (every isolation level)
  `testAMoveOutFromUnderTheLinkedTenantSuspendsTheLinkInTheMovesTransaction`, `testAMoveThatRollsBackSuspendsNothing`,
  `testAMoveOfASubtreeHoldingAnotherTenantTypeIsRefused`;
  `testWithTheSsoSwitchOffNobodyIsReported`, `testThePeopleGrantedAreReadFromEveryGrantTableEachOnce`
- `tests/Integration/EndToEnd/GroupGrantsThroughSsoTest.php` (every isolation level)
  `testAFirstSignInIsGrantedWhatItsGroupsMapTo`, `testARefusedMappingRollsTheProvisioningBack`,
  `testALaterSignInReSyncsTheGroups`, `testTheReSyncTakesTheIdentityGuardOnlyOnceTheRedemptionHasCommitted`,
  `testARefusedReSyncHandsOutNoCredential`
- `tests/Integration/EndToEnd/TenancyThroughSsoTest.php` (every isolation level)
  `testTheShippedGrantHalfLinksAMemberWithinTheTenant`, `testTheShippedGrantHalfLinksNobodyGrantedBeyondTheTenant`
- `tests/Feature/Authorization/AuditAccessSeamTest.php` `testThePolicyIsBoundOverAuditLogsDefaultInEveryProviderOrder`,
  `testTheRowIsSharedAndNeverMandatory`; `tests/Integration/Authorization/AdministrativeCheckTest.php`
  `testAGrantInTheObjectsTenantAllowsTheOperationThere`; `tests/Integration/Authorization/AuditAccessPolicyAdapterTest.php`
  `testTheScopeIsNeverWiderThanAnyTenantsGrant`; `tests/Integration/Audit/AuthorizationRecordsTest.php`
  `testARolesLifeIsRecordedCallByCall`
- `tests/Feature/Authorization/DecisionCacheInvalidationTest.php`
  `testTheLastDecisionIsForgottenWhenItDependedOnTheChange`, `testWithNoSessionNamedOnlyTheIdentityIsMatched`,
  `testAnIdentityThatIsNoModelIsMatchedByTheSessionAlone`, `testADecisionRecordedBeforeARollbackIsForgottenAgain`,
  `testADecisionRecordedBeforeACommitIsKept`,
  `testADecisionRecordedAfterACommittedSavepointIsForgottenWhenTheEnclosingTransactionRollsBack` (run on Laravel 12 and
  13), `testWithNoTransactionsManagerTheChangeForgetsAtOnce`, `testOutsideATransactionTheChangeWaitsOnNothing`
- `tests/Integration/Authorization/DecisionCacheInvalidationTest.php` (every isolation level)
  `testAFactorRemovedForgetsTheAllowThatReadItsProof`,
  `testAVerificationPassedForgetsTheRefusalThatReadTheProofsBeforeIt`
- `tests/Integration/Mfa/SessionTransitionAdapterTest.php`
  `testTheDecisionThatReadTheSessionsAuthenticationIsForgotten`; `tests/Integration/Mfa/PendingCompletionAdapterTest.php`
  `testTheDecisionThatReadThePendingSessionsAuthenticationIsForgotten`;
  `tests/Integration/Mfa/SessionRevokerAdapterTest.php`
  `testRevokingAllForgetsTheDecisionThatReadTheIdentitysAuthentication`; `tests/Integration/Mfa/StepUpAdapterTest.php`
  `testTheDecisionThatReadTheSessionsAuthenticationIsForgotten`
- `tests/Feature/Storage/ConnectionAlignmentTest.php` `testAlignWritesTheSharedConnectionIntoEveryUnsetMemberKey`,
  `testAssertAlignedRefusesAMemberKeyNamingAnotherConnection`,
  `testAssertRegisteredRefusesAMemberWhoseProviderHasNotRegistered`,
  `testUnsetMemberKeysReceiveTheSharedConnectionInAnyOrder`
- `tests/Feature/Scheduling/IamScheduleTest.php` `testOnlyThePrunesAreScheduledWhileSsoIsNotInUseAndDeliveryIsSync`;
  `tests/Feature/Checks/SchedulesCheckTest.php` `testThePrunesAreNotedUntilThePackageSchedulesThem`
- `tests/Feature/Checks/CrossMemberConfigurationCheckTest.php`
  `testTheResourceTenantResolverIsNotedWhilePeopleActInTenants`,
  `testTheTenantResolverMustResolveWhileATenantsRuleReachesASession`, `testGrantsNeedNoResolverWhileSsoIsOff`,
  `testTheTenantResolverMustResolveWhileAuthorizationReadsATree`

## Change Triggers

- `laravel-authorization` binds its defaults unconditionally again, or renames its `authorization.default:` prefix, its
  configuration keys or its defaults.
- `laravel-authorization` changes how it matches an assurance key, or reads the context's types itself.
- `laravel-authentication`, MFA or SSO adds a key that says how strongly or how recently the session was authenticated:
  it joins `ASSURANCE_KEYS`.
- `laravel-authorization` caches decisions across checks, or drops the last decision on a change to its session's
  proofs, or offers a way to forget the decisions of a session or identity: `DecisionCacheInvalidation` calls that
  instead.
- `laravel-authorization` renames `authorization.connection` or `authorization:prune`, gives the prune a constant of its
  own, or lets `authorization:check` fail.
- `laravel-authorization` binds its resource tenant resolver so the configured class can be read from the binding: the
  note reads the binding alone.
- `laravel-authorization`'s grant widening carries a client, or its hook runs under its own locks, or a try runs again
  inside the application's transaction: the hook passes the client on, and the lock order and retries here change.
- `laravel-authorization` names a tenant by an identifier of its own, or its default identity directory becomes complete
  under another subject resolver: `TenantTranslator` and `IdentityDirectoryAdapter` change or go.
- `laravel-authorization` adds a query for the tenants where a subject holds an action, or decides a named subject in its
  own tenant: the audit access policy and `AdministrativeCheck` use it.
- SSO's `widened()` takes a client the widening can carry, or stops requiring a transaction on its storage connection.
- `laravel-authentication` adds a namespace of its own to the context, or carries a credential's scopes on its caller.
- MFA adds an assurance level, or a requirement part.
- Laravel stops turning an authorization exception into an HTTP exception before its render callbacks, or stops keeping
  it as the previous exception.
