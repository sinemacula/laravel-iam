# Authorization

## Purpose

This note describes how the package binds `laravel-authorization` to the other members (FEATURES section 6): its subject
resolver, answered from `laravel-authentication`'s caller (IAM-6.1); its authentication context,
`laravel-authentication`'s, with the `mfa` and `sso` namespaces (IAM-6.2); its requirement checker, answered by MFA's
requirement check on the proofs of the subject's own session (IAM-6.3); its insufficient-authentication exception,
rendered as MFA's step-up (IAM-6.4); its session policy source and `laravel-authentication`'s scope registry, answered
from the caller's credential scopes and from `laravel-authorization`'s registry (IAM-6.5); and
`laravel-authentication`'s application access, answered from `laravel-authorization`'s grants (IAM-6.6). It covers how
the binding rule replaces a member that binds its defaults unconditionally, when the access contracts are mandatory,
what the second part of this work still adds, and the gaps in the members the adapters work around. The rule itself is
in `binding-precedence.md`, and the worker reset in `long-running-processes.md`.

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

  Three of `laravel-authorization`'s four are never mandatory: each default refuses (no tenant, every requirement unmet)
  rather than admits. The session policy source's default caps no person and allows nothing only to a machine principal
  carrying `AuthorizableMachine`, so a `laravel-authentication` machine without that marker is capped by nothing; it and
  the scope registry are mandatory while a guard accepts `api_key` or `client_credentials`, as the bound application
  policy says, and application access while `authorization.application_access` maps an application
  (`Authorization\AccessMandates`). `laravel-authentication`'s tenant access is not `laravel-authorization`'s to answer
  (AUTHZ-13.8), and stays on `OwnTenantOnly`.
- The subject resolver is scoped, as `laravel-authorization`'s own default is: its resolved tenant is kept for the
  request only while `ResolvedTenant::isFrom()` finds the resolver bound to be the very one that resolved it, by
  identity. A transient resolver would resolve the subject again on every tenant-scoped read (`TenantScope::scopeKey()`,
  `currentChain()`, the tenant scope on its roles, permissions and policies), and each new tenant, bound with
  `instance()`, fires `laravel-authorization`'s rebinding listener, which empties the request's resolution memo, so
  every check would read its grants again. The adapter still reads `Auth::caller()` afresh on each call.
- `laravel-authorization` binds every default unconditionally: its provider scopes the class its configuration names
  under `authorization.default:` and the contract, and binds the contract with a plain `bind()` to a closure it declares
  that resolves that key (IAM-13.7 still says a plain `singleton`; at the commit this package requires it is a plain
  `bind()` over a scoped key, unconditional either way). So each of its rows names the provider and the default class,
  and the key (`AuthorizationSeams::authorizationRow()`, `SeamBinding::$defaultKey`): the seam is replaced only while
  the closure is the provider's and the key still holds the default class. A class the application names in
  `authorization.subject_resolver`, `authorization.requirement_checker` or `authorization.session.source` is bound by
  `laravel-authorization` with the very same closure, and is kept, as is anything the application binds over the
  contract.
- Registering after this package, `laravel-authorization` replaces the adapters. The booting callback binds each one
  the rule bound again where the seam holds the member's own closure once more (`BindingRule::reclaim()`), before any
  provider boots, so before `laravel-authorization`'s boot builds its authentication context, and the `booted()`
  callback does so once more, for a `laravel-authorization` another provider registers from its `boot()`. Whatever
  another provider's `boot()` resolved from the defaults in between would keep them: the manager, holding the default
  subject resolver and with it the default session cap, check context factory and requirement checker, and the key
  catalogue, a singleton built without the context's keys. So when that last pass binds any seam again, the suite's
  scoped state is forgotten as a worker forgets it between jobs (`WorkerReset::forgetScopedState()`: the manager, the
  check context factory, the resolved tenant, the `authorization.default:` and `iam.scoped:` keys, and every facade's
  root), and the context's keys are declared on a catalogue already built
  (`AuthenticationContextKeys::declareOnResolved()`). The key
  holds the default while it holds the default class, or an instance of exactly that class resolved there, as
  `laravel-authorization`'s boot leaves its authentication context. A seam holding anything else is kept: the
  application's binding, made in its own provider's `register()` after the packages', the member's default class bound
  by name among them, since a member binding through a closure never binds a class name. A binding the application made
  before this package registered, which the rule kept, is overwritten by `laravel-authorization` too: the rule records
  what binds it again as it keeps it (`MemberDefaults::restorerOf()`, `BindingOutcome::$restorers`) and `reclaim()`
  binds it back the same way. One made after this package registered and before `laravel-authorization` did is lost to
  `laravel-authorization` itself, which no rule of this package can undo. `iam:check` refuses each of these rows the
  outcome lists, bound or kept, whose live binding holds `laravel-authorization`'s own default again
  (`MandatorySeamsCheck::decidedChecks()`), so a member registered once neither callback can run is not passed silently.
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
  names untouched. A namespace an application's own contributor adds is not supplied. It is scope invariant.
- The keys (`AuthenticationContextKeys`). Each key of the three namespaces is declared on `laravel-authorization`'s key
  catalogue with its type, once, as the catalogue is built, while the context bound is this package's. Those that say
  how strongly or how recently the session was authenticated are declared untestable, beyond the ones
  `laravel-authorization` makes untestable itself: `authentication.mfa` and `authentication.recovery_code`, MFA's
  verdicts (`mfa.accepted`, `mfa.factor_types`, `mfa.level`, `mfa.phishing_resistant`, `mfa.user_verification`,
  `mfa.last_verification_age_seconds`) and SSO's record of the provider's authentication (`sso.provider_auth_time`,
  `sso.provider_amr`, `sso.provider_acr`, `sso.provider_authn_context_class_ref`), so a policy states an
  `authentication_requirement` instead. A key already declared, by `authorization.context.keys` or an attribute
  provider, keeps its declaration.
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
  `WriteConnection::during()`, so the grants are read from the primary. `laravel-authorization` decides with the session
  caps applied, and a principal being admitted holds no credential yet, so a machine principal is refused on any
  application the map names (a member gap, below). An application the map does not name is open to every principal,
  people included, whatever its grants, as `laravel-authorization` decides (`mayUse()` answers `true` for it), and the
  adapter changes nothing of that: leaving an application out of the map to let machines call it opens it to everyone,
  and `iam:check` raises nothing, since the mandate holds while the map names any application. An application whose
  machines call it binds an `ApplicationAccess` of its own, or accepts that it is open. The adapter keeps nothing, but
  is bound scoped under `iam.scoped:`, as IAM-6.6 asks.
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
  closure that resolves its `authorization.default:` key, the check names a seam still holding that closure by what the
  key holds (`MandatorySeamsCheck::holderOf()`): `NoSessionPolicy` is refused, and a class the application names in
  `authorization.session.source` passes.
- Request state. None of the adapters keeps anything between calls. The subject resolver and application access are
  scoped all the same, under `iam.scoped:` (`BindingRule::bindScoped()`), so the seams themselves are never scoped, and
  the worker reset and Laravel's `forgetScopedInstances()` forget them between units of work. The caller
  `laravel-authentication` keeps on the request is dropped by the worker reset (above).
  `laravel-authorization`'s own request state, what its previews know and the console subject resolver its explanations
  resolve through included, is scoped, and the worker reset forgets it with every `authorization.default:` key; its
  explanations keep nothing beyond the check.

## Success Path

1. The provider registers. The binding rule binds the six rows over the members' defaults where the switch is on; the
   requirement checker only while `iam.adapters.mfa` is on too. The context's keys are queued for the key catalogue.
2. The booting callback runs before any provider boots, and binds again any of `laravel-authorization`'s seams it
   replaced after this package registered, the adapter or the application's binding the rule kept; the `booted()`
   callback does the same once every provider has booted, and, when it binds anything again, forgets what was resolved
   from the defaults meanwhile and declares the context's keys on a catalogue already built.
3. `laravel-authorization` boots, reads the context's namespaces, and later builds its key catalogue, with the
   context's keys declared on it.
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
- A machine principal is refused on an application `authorization.application_access` maps, since an admission holds
  no credential whose scopes could cap it: `laravel-authorization`'s rule. An API key cannot be issued to it for such
  an application. An application the map leaves out is open to every principal, a person with no grant included.
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
  - `laravel-authorization` binds every default with a plain `bind()` over its scoped `authorization.default:` key
    (`bindScopedDefault()`), never `bindIf()`, so an application binding made before it registers is lost and the
    adapters bound before it are overwritten (IAM-13.7, still open in substance: its resolvers moved from a plain
    `singleton()` to a plain `bind()` over a scoped key, unconditional either way). The rows name the provider, the
    default class and the key, `BindingRule::reclaim()` binds the adapters and the application's kept bindings again
    from the booting and the `booted()` callbacks, and `iam:check` refuses what neither could bind back; with
    `bindIf()` none of it would be needed.
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
  - `laravel-authorization` reads `AuthenticationContext::namespaces()` once as it boots (its context configuration
    validation) and once into a singleton key catalogue, both before a sibling's contributors register, so the adapter
    answers a fixed list. Reading the namespaces per check, or documenting that they must not change, would close it.
  - `laravel-authorization`'s assurance keys (`AssuranceKeys`) do not cover the keys the suite's context carries that say
    how the session was authenticated (`authentication.mfa`, `recovery_code`, MFA's verdicts, SSO's `provider_*`), so
    `AuthenticationContextKeys` declares them untestable itself.
  - `laravel-authorization`'s `Services\ApplicationAccess::mayUse()` decides with the session caps applied, though an
    admission holds no credential whose scopes could cap it, so a machine principal is always refused on a mapped
    application. Deciding application access without the session stage, a grant question rather than a credential's,
    would close it; `ApplicationAccessAdapterTest` pins today's answer, so the fix shows. It also answers `true` for any
    application the map does not name, so the only way to let a machine use an application through it is to open the
    application to every principal.
  - `laravel-authentication`'s caller carries no credential scopes (they live on `ContextualGuard::scopes()` alone), which
    forces the session policy source's ambient read. Scopes on `Caller`, filled as the access credential is admitted,
    would let the subject carry them and the source take them as a plain value.
  - `laravel-mfa` builds its step-up exception only in its middleware, and the confirmed-factor read it uses
    (`ConfirmedFactors`) is `@internal`, so the mapping derives whether a confirmed factor is held from `Mfa::factors()`.
    A public factory for the step-up exception from a caller and a requirement would close it.
- Still to come (the second part of this work): the grant hook calling SSO's scope widening and the grant scope query
  behind SSO's principal scope; the tree seam and `treeChanged()`; group mapping and re-sync; the permission catalogue
  and the administrative check; the audit access policy; decision cache invalidation; the authorization audit mapper and
  codes; `authorization.connection` aligned to the storage connection; `authorization:prune` in the schedule; and a
  resource tenant resolver named by `iam:install`. `authorization:check` already runs inside `iam:check`.

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
- The binding rule's own units change (`Bindings\BindingRule`, `Bindings\MemberDefaults`, `Bindings\SeamBinding`,
  `Bindings\BindingOutcome`), and `iam:check`'s seams check refuses a decided seam back on its default, because
  `laravel-authorization` binds its defaults unconditionally (IAM-13.7), which the manifest, expecting its resolvers to
  be named in configuration, did not foresee. For the same reason `iam:install` writes none of
  `laravel-authorization`'s resolver keys and `CrossMemberConfigurationCheck` requires none (`install-and-check.md`).

## Implementation Anchors

- `src/Authorization/AuthorizationSeams.php`: `seams()`, `isOn()`, `authorizationRow()`, `SWITCH`,
  `DEFAULT_KEY_PREFIX`; `src/IamServiceProvider.php`: `seamProviders()`, `settle()`; `config/iam.php`:
  `adapters.authorization`.
- `src/Bindings/SeamBinding.php`: `$defaultKey`, `isMandatory()`; `src/Bindings/MemberDefaults.php`: `isReplaceable()`,
  `holdsDefault()`, `restorerOf()`; `src/Bindings/BindingRule.php`: `apply()`, `reclaim()`;
  `src/Bindings/BindingOutcome.php`: `$restorers`; `src/Checks/MandatorySeamsCheck.php`: `decidedChecks()`,
  `holderOf()`.
- `src/Authorization/SubjectResolverAdapter.php`: `resolve()`, `forUser()`.
- `src/Authorization/AuthenticationContextAdapter.php`: `namespaces()`, `values()`, `NAMESPACES`;
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

## Authoritative Tests

- `tests/Feature/Authorization/AuthorizationSeamsTest.php`
  `testEveryAdapterIsBoundOverItsMembersDefaultInEveryProviderOrder`,
  `testAClassTheApplicationNamesInAuthorizationsConfigurationIsKept`,
  `testAnApplicationBindingMadeOnceEveryProviderHasRegisteredWins`, `testTheSwitchOffBindsNothing`,
  `testTheRequirementCheckerFollowsTheMfaSwitch`,
  `testEachRowReadsLaravelAuthorizationsDefaultKeyAndOnlyTheResolverIsScoped`,
  `testTheSubjectResolverIsOneForAUnitOfWork`,
  `testTheSwitchIsReadLeniently`, `testTheContextsKeysAreDeclared`, `testAKeyTheApplicationDeclaresKeepsItsDeclaration`,
  `testNoKeyIsDeclaredForAnApplicationsOwnContext`, `testAnAuthorizationRegisteredWhileBootingHasEveryAdapterBoundAgain`,
  `testWhatIsResolvedFromTheDefaultsWhileBootingIsBuiltAgainWithTheAdapters`,
  `testTheKeysAreDeclaredOnACatalogueAlreadyBuiltOnly`,
  `testAnApplicationBindingMadeBeforeAuthorizationRegistersAfterThisPackageIsKept`,
  `testIamCheckRefusesASeamLaravelAuthorizationBoundItsDefaultOverAgain`
- `tests/Feature/Authorization/AccessSeamsTest.php` `testEveryAdapterIsBoundOverItsMembersDefaultInEveryProviderOrder`,
  `testASourceTheApplicationNamesInAuthorizationsConfigurationIsKept`,
  `testTheAccessSeamsAreMandatoryWhileTheConfigurationSaysSo`, `testIamCheckRefusesTheDefaultSourceWithTheSwitchOff`,
  `testIamCheckRefusesTheDefaultSourceTheApplicationBindsByName`,
  `testIamCheckPassesASourceTheApplicationNamesInAuthorizationsConfiguration`,
  `testIamCheckAsksTheBoundApplicationPolicyWhichMachineCredentialsAGuardAccepts`,
  `testTheApplicationPolicyIsAskedOnlyWhenTheMandateIsRead`
- `tests/Unit/Bindings/MemberDefaultsTest.php` `testASeamResolvingAKeyThatHoldsTheDefaultIsReplaceable`,
  `testASeamResolvingAKeyThatHoldsAnotherClassIsKept`, `testADefaultClassBoundByNameIsNoMembersOwnBinding`,
  `testAClosureNoMemberDefaultDeclaresIsNoMembersOwnBinding`, `testAKeyHoldingAResolvedInstanceIsJudgedByItsClass`,
  `testAKeyResolvedTransientlyIsNotBuiltToBeJudged`, `testWhatBindsASeamAgainRebindsItAsItWas`
- `tests/Feature/Bindings/BindingRuleTest.php` `testReclaimingBindsAgainOnlyTheSeamsAMemberBoundItsDefaultOver`,
  `testReclaimingBindsAgainTheApplicationsBindingAMemberBoundItsDefaultOver`
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
  `testAMachineIsRefusedOnAnApplicationTheMapNames`
- `tests/Unit/Workers/WorkerResetTest.php` `testResetForgetsTheMembersScopedState`,
  `testResetForgetsThePackagesScopedAdapters`, `testForgettingTheMemberStateDropsTheRequestsCallers`

## Change Triggers

- `laravel-authorization` binds its defaults with `bindIf()` or `scopedIf()` (IAM-13.7): `reclaim()` then has nothing to
  do for it, and a binding the application makes before it registers survives.
- `laravel-authorization` renames its `authorization.default:` prefix, its configuration keys or its defaults.
- `laravel-authorization`'s assurance keys grow to cover `mfa`, `recovery_code`, MFA's verdicts or SSO's provider keys:
  the untestable declarations here become redundant.
- `laravel-authentication` adds a namespace of its own to the context, or carries a credential's scopes on its caller.
- MFA adds an assurance level, or a requirement part.
- Laravel stops turning an authorization exception into an HTTP exception before its render callbacks, or stops keeping
  it as the previous exception.
