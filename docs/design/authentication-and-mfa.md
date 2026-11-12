# Authentication and MFA

## Purpose

This note describes how the package joins `laravel-authentication` and `laravel-mfa` (IAM-3.1 to IAM-3.8, IAM-3.11,
IAM-3.12, IAM-3.14 and IAM-5.2). It covers the twelve seams `Mfa\MfaSeams` binds, the `mfa` namespace this package
contributes to `laravel-authentication`'s authentication context, how an MFA sign-in is resolved to one of
`laravel-authentication`'s sessions, how the members' value types are translated, how each adapter answers and
refuses, and the transactions and lock order the adapters run in. Code challenges, passkeys, the context resolvers and
code delivery (M3) are in `codes-delivery-and-passkeys.md`.

## Invariants

- `Mfa\MfaSeams` declares every binding, and the binding rule applies them in `register()` (see
  `binding-precedence.md`). An adapter replaces only the member's own default; a binding the application made, before or
  after the members register, is kept (IAM-8.4). Every adapter is transient and reads the guard's state on every call,
  so none holds request state between calls (IAM-8.1). Only the session revoker is mandatory (IAM-3.7): left on MFA's
  default, a removed factor would leave the identity's other sessions standing.

  | Member seam                      | Adapter                         | Member default replaced                     |
  | -------------------------------- | ------------------------------- | ------------------------------------------- |
  | AUTH `AdditionalFactorPolicy`    | `AdditionalFactorPolicyAdapter` | `NeverRequireAdditionalFactor`              |
  | AUTH `RequirementCheck`          | `RequirementCheckAdapter`       | `MeetNoRequirement`                         |
  | MFA `PendingSessionResolver`     | `PendingSessionResolverAdapter` | `NoPendingSessionResolver`                  |
  | MFA `PendingCompletion`          | `PendingCompletionAdapter`      | `ProofStoreCompletion`                      |
  | MFA `StepUp`                     | `StepUpAdapter`                 | `ProofStoreCompletion`                      |
  | MFA `Reauthenticator`            | `ReauthenticatorAdapter`        | `RefusingReauthenticator`                   |
  | MFA `FreshnessGate`              | `FreshnessGateAdapter`          | `ConfiguredFreshnessGate`                   |
  | MFA `FactorChangeGate`           | `FactorChangeGateAdapter`       | `ConfiguredFactorChangeGate`                |
  | MFA `SessionRevoker` (mandatory) | `SessionRevokerAdapter`         | `GenerationSessionRevoker`                  |
  | MFA `SessionTransition`          | `SessionTransitionAdapter`      | `MiddlewareSessionTransition`               |
  | MFA `ProofStore`                 | `ProofStoreAdapter`             | the closure `Proofs\ProofBindings` declares |
  | MFA `FirstFactorResolver`        | `FirstFactorResolverAdapter`    | `DeclaredFirstFactorResolver`               |
  | MFA `VerifiedSignInRecorder`     | `VerifiedSignInRecorderAdapter` | none: MFA binds no default                  |

- The whole capability is switched by `iam.adapters.mfa` (`IAM_ADAPTERS_MFA`), read in `register()` and leniently:
  `false` (as a boolean or as text), `0`, `off` and `no` turn it off, and anything else, a missing or empty value
  included, leaves it on. Off, nothing here is bound and each member keeps its own default. A test that changes it
  must do so before the providers register (`#[WithConfig(MfaSeams::SWITCH, false, defer: false)]`).
- One core method for each action, taking plain values: every adapter's core path (each seam method MFA or
  `laravel-authentication` calls with the values of an action, and each call this package makes into a member) takes the
  caller, the client, the credential and the application as values, never an `Illuminate\Http\Request`, and has no
  second variant for the same action. Only an edge reads a request: `PendingSessionResolverAdapter::fromRequest()`,
  through `laravel-authentication`'s `PendingCredential::extract()`, and `ApplicationResolverAdapter`'s `resolve()` and
  `resolveForGuard()`, one core method (`resolve()` names the default guard through `resolveForGuard()`), whose
  `Request` MFA's contract hands it and which read nothing of it, the guard being the one value they need. No adapter
  reaches for the request the container holds (`make('request')`, `request()`, the `Request` facade), so a request bound
  beside a core call never changes what it does. Each member's `ClientContext` is its own class: the two cross in one
  place (`Mfa\Translation\ClientTranslator`, `toAuthentication()` and `toMfa()`), one to one, with the IP address, user
  agent, `Origin`, scheme and host and the names of the headers carried, the last three cleaned alike by both members,
  and where MFA hands no client `laravel-authentication` is handed one of which nothing is known
  (`ClientTranslator::unknown()`).
- A sign-in is one of `laravel-authentication`'s sessions, named as MFA names a sign-in (`Mfa\Translation\SignIn`):
  - MFA's application is the guard of the same name, which must be a declared guard of the `jwt` driver. MFA hands every
    self-service seam its caller as plain values (`CallerContext`: the identity, a pending session or nobody, the
    application and the client), and a removal its application, and those are what the adapters act on, never the
    guard's current user. Only where MFA names no application (the pending session resolver's `fromRequest()`, a reset)
    is it the default guard, as `Auth::shouldUse()` leaves it, which is also what MFA names its application after when
    it reads a caller through no guard of its own. The event context reads no guard: it names
    the session of the sign-in MFA hands it on the application MFA hands it, read by its key, and MFA names the event's
    application itself.
  - MFA's sign-in id is the session's key as a string (`SignIn::reference()`), which is always its primary key. A key
    that is neither a non-empty string nor an integer names nothing and is refused.
  - Where `laravel-authentication` names no session (at sign-in, before the session row is written, and whenever it
    asks for a requirement), every proof of the judgement is bound to `SignIn::UNNAMED` (`iam:unnamed-session`). It
    holds a colon, so no session key can equal it, and no adapter that reads a session's proofs produces it.
  - The identity is named by MFA's `ProofOwner`: its morph class for an Eloquent model and its class name otherwise,
    and its key, which must be an integer or a non-empty string.
  - Every proof read from a session is stamped with the identity's current MFA verification generation
    (`VerificationGeneration::current()`, one read), since MFA trusts a proof only under the current generation.
- `Mfa\CurrentSession` resolves the guard and the sign-in for every adapter, so every adapter refuses the same
  misconfiguration the same way:
  - `defaultGuard()`, `guard()`, `sessions()` (the guard's session service) and `identitySessions()` (the session
    service a change to the identity as a whole goes through: the default guard's when it is a `jwt` guard, otherwise
    the first `jwt` guard declared); `caller()` (the identity the guard serves) is asked only by the testing helper
    that verifies the acting session (`Testing\VerifiedSession`), never by an adapter, which MFA hands its caller;
  - `current()` (the guard's current session, when it is the identity's), `held()` (the same, or `null` when the
    guard holds none of the identity's), `of()` (that session, when it is also the sign-in MFA named) and `identity()`
    (MFA's identity as `laravel-authentication`'s). MFA's caller carries no sign-in, so where MFA names none (the
    freshness gate, the reauthenticator, the proof store's `currentSession()`, `proofs()` and `firstFactor()`) the
    caller's session is the guard's current session held by the caller's identity, which is also what MFA's own proof
    store answers as the caller's sign-in. Where MFA does name the sign-in (a factor change's request, a session
    transition, a revocation), the adapters resolve it by that key through `named()`, whatever the guard holds now, so
    a change made off the request that holds it (a queued job's, a console command's, a request another guard serves)
    acts on the sign-in MFA named. `named()` reads the session through the identity's own `sessions()` relation on the
    write connection (`laravel-authentication`'s `WriteConnection`, with `SessionKeyShape` keeping a key that cannot be
    the session model's from the query), so another identity's session is never found; one of another guard's, or
    none, throws `UnresolvedReferenceException` of kind `session` (`forSignIn()`) inside the transaction. Whether it is
    still live and active is `laravel-authentication`'s to judge under its row lock, in the call it is handed to. The
    step-up needs no session at all: `stepUp()` steps up the session the proof's binding names. `of()` (the guard's
    current session, when it is also the sign-in named) is left to the proof store's `record()`, whose contract is
    the identity's current sign-in;
  - `isInTransaction()`: whether a transaction is open on `laravel-authentication`'s storage connection, the one its
    session model must live on, which decides how an adapter asks the freshness policy (see below).
  - An application that is no declared `jwt` guard on `laravel-authentication`'s auth manager (an `api_key` guard
    included) throws `Exceptions\UnresolvedReferenceException` of kind `guard` from `guard()`, and so from every method
    that resolves a guard: a misconfiguration, told apart from a guard that holds no session of the identity now (kind
    `session`). An identity that is not `laravel-authentication`'s, or whose key names nothing, is kind `identity`
    (`forIdentity()`), as is one that is `laravel-authentication`'s but not MFA's `MultiFactorAuthenticatable`
    (`forMfaIdentity()`, whose message names that contract). A guard holding another of the identity's sessions than
    the one named throws `Exceptions\SessionMismatchException`.
- Translation (IAM-3.14, IAM-5.2) is pure and lives in `Mfa\Translation`:
  - Proof kinds, purposes, channel kinds, key protections, assurance levels, requirement parts, factor changes, factor
    changes made and pending actions are spelt the same by both members and cross by value. `laravel-authentication`'s
    `external_reauthentication` is MFA's `first_factor_reauthentication` on an `external_provider` channel, with the
    purpose `reauthenticate` it was recorded with; its channel reference is kept only when it was recorded on the
    provider's channel. An SSO sign-in is a `first_factor` on the `external_provider` channel, and a link records no
    proof.
  - MFA's `unclassified` level is no level. MFA refuses a channel reference on `password` and `unknown`, so it is
    dropped; a recovery code has no channel in MFA and the `unknown` channel in `laravel-authentication`.
    `backupEligible` and `phishingResistant` are MFA's `backupEligibility` and `phishingResistance`. A further factor's
    `factor` is MFA's `reference`. Channels cross as MFA's array form (`kind`, `reference`).
  - A verified result crosses as `laravel-authentication`'s proof result bound to the proof's identity, application,
    sign-in and purpose, made at the proof's `provedAt`, with its `amr` without `mfa`, and with the proof's own
    evaluation (`ProofTranslator::toResult()`), never MFA's evaluation of the whole session the result carries.
- The evaluation a further proof is recorded with (IAM-3.2, IAM-3.5): `laravel-authentication` keeps it on the proof's
  own row, and its freshness reads "multifactor within so many seconds" as the newest proof flagged multifactor, timed
  by that proof. So the proof is recorded accepted, as MFA hands over only a proof it accepted after the session's first
  factor, and multifactor exactly when `VerificationResult::$refreshesMultifactor` says so: when the freshest evidence
  that the first factor and this proof are multifactor, as MFA's requirement check judges the two alone
  (`Evaluation::$multifactorAt`), is this proof's own. Never MFA's `VerificationResult::$evaluation`, which judges every
  proof of the session together and would flag a fresh email code multifactor because of an authenticator app code
  proved hours before. A password followed by a fresh authenticator app code is flagged; a passkey sign-in that
  verified the person followed by an email code is not, while one followed by a fresh passkey is; an older further
  proof the session holds never counts; and a combination policy that does not date its multifactor evidence leaves
  every proof unflagged.
  - `laravel-authentication`'s `REPLACE` change, its `OTHER` change made and its `list_principals` and
    `choose_principal` pending actions have no MFA counterpart: the first two never reach MFA, and the actions are
    left out of a pending context.
  - Anything one member would refuse, a maximum age over a year among them, is refused with that member's own
    `InvalidArgumentException`, never shortened or dropped.
  - Freshness (`RequirementTranslator::toFreshnessParts()`, `toFreshness()`, `fromFreshness()`): a freshness
    requirement holds what a stored proof shows. An additional verification is a further factor or a recovery code
    within the part's age; multifactor authentication and phishing resistance are the flags of the same names on a
    proof of any kind; a minimum assurance level, which no stored proof records, is refused. Asked part by part (the
    freshness gate), a part with no maximum age is refused, as MFA's contract asks; asked as a whole (the factor-change
    gate, from MFA's configuration), the parts become one requirement held to the shortest age, a part with none or a
    longer one held to a day. Back the other way, a setting that takes only further factors and recovery codes is an
    additional verification, and its flags are their parts.
- Each adapter in turn:
  - `AdditionalFactorPolicyAdapter` (IAM-3.1) asks MFA's requirement policy alone, with the first factor as MFA's
    proof, and returns its answer part for part and age for age.
  - `RequirementCheckAdapter` (IAM-3.2) judges the subject's first factor, then the further proofs oldest first, with
    MFA's requirement check, and answers the parts MFA leaves unmet. The proofs are read in one bounded query:
    reauthentications with the first factor, further factors and recovery codes, made since the longest part's age
    (all of them when a part has none), at most `RequirementSubject::MAX_LIMIT`. A part met only by an older proof is
    left unmet. A reauthentication at an external provider is not read, as `laravel-authentication` counts no part met
    by one.
  - `PendingSessionResolverAdapter` (IAM-3.3) has one edge and one core method. `fromRequest()`, the one place a
    request is read, takes the pending credential with `laravel-authentication`'s own extractor
    (`PendingCredential::extract()`: the body field `authentication.session.pending_credential_field`, from the JSON
    body or the form body of a request other than `GET` and `HEAD`, never the query string) and answers
    `Auth::sessions()->pending()` on the default guard as MFA's pending context, which keeps the credential, hidden.
    No field is no pending session; a field that names no live pending session is refused. `revalidate()`, asked under
    MFA's lock, reads no request: it reads the session again from the credential the context keeps, on the context's
    application, and answers `null` (MFA's refusal) for a context that kept none, a session that ended, and another
    session or identity than the context's. `fromCredential()` reads no request either: it answers the pending session
    a credential handed in as a plain value names on the application's guard, or `null`, for the passkey factor gate
    (`codes-delivery-and-passkeys.md`).
  - `PendingCompletionAdapter` (IAM-3.3) is handed the caller the verification was served to: it reads the pending
    session from `CallerContext::$pending`, and refuses a caller holding none as `not_accepted`, as it refuses a
    result bound elsewhere, before anything is written. It calls `satisfy()` with the credential the revalidated
    context keeps, the proof's own evaluation and the caller's client (`Translation\ClientTranslator::toAuthentication()`)
    as the last write of MFA's transaction, only inside a transaction on the storage connection, and returns the
    `SignInResult` as MFA's completion. `satisfy()` binds the guard only once that transaction commits, so a result
    never reaches a response when MFA's commit fails. `laravel-authentication` judges the client: on a guard whose
    refresh token travels in a cookie, a client without an `Origin` of its own site or the guard's custom header is
    refused as `cross_site_request` (thrown as `not_accepted`, inside MFA's transaction, which rolls back), and the
    activation records the client's IP address and user agent as the session's last use.
  - `StepUpAdapter` (IAM-3.4) refuses a caller that is pending, nobody or on another application than the proof's,
    checks the proof names the caller's identity, and calls `stepUp()` with the proof's own evaluation and the caller's
    client, which steps up the session the proof's binding names, never the guard's current one, locking its row
    after MFA's locks and checking it is the identity's live, active session on the guard; the `AccessTokenResult` is
    MFA's completion.
  - `ReauthenticatorAdapter` (IAM-3.5) checks the session is live through `firstFactor()` (locking its row inside a
    transaction) and answers the newest reauthentication `FreshnessPolicy::freshProof()` finds for
    `first_additional_factor` within MFA's five minutes; a session no longer live answers none.
  - `FreshnessGateAdapter` (IAM-3.5) asks `FreshnessPolicy::freshUntil()` about the caller's session (the current
    session of the caller's application's guard, when it is the caller's identity's; a pending caller and nobody are
    never fresh) for each part of the caller's requirement, each made stricter by the application's own setting in
    `laravel-authentication`, and answers the earliest end. `requirement()` reads no proof.
  - The read mode of both (`freshProof()` and `freshUntil()`'s `$current`) follows where MFA asks them, through
    `CurrentSession::isInTransaction()`:
    - Outside a transaction on the session model's connection (MFA's route gate and `Mfa::isFresh()` for the freshness
      gate; MFA's contract kits, or a caller of the application's, for either) nothing acts on the answer atomically, so
      they ask plainly: no lock, and the policy, which throws a `LogicException` for a current judgement outside a
      transaction, answers.
    - Inside one (MFA's own `ConfiguredFactorChangeGate`, which an application may bind back in place of this
      package's gate, asks both inside MFA's transaction, after its locks, and grants the change on the answer, its end
      from `freshUntil()`) they ask current: the policy locks the session's row until the transaction ends and reads its
      proofs as committed, so a proof voided before the call never counts and one recorded before it does, whatever
      the transaction read first.
    - It is the line `laravel-authentication`'s own reads of a session's proofs and first factor draw too, so every
      adapter that reads a session's proofs reads them the same way. An application that asks `Mfa::isFresh()` inside
      a transaction of its own gets the current answer, and the session's row stays locked until it ends.
  - `FactorChangeGateAdapter` (IAM-3.6) calls `factorChange()` on the sign-in MFA names, with MFA's configured
    requirement as a whole, in place of MFA's own freshness check, and answers until when the session stays fresh.
    `laravel-authentication`'s gate judges the session under its lock on its proofs as committed (it asks its freshness
    policy current), so a step-up voided before the gate never allows a change and one recorded before it does,
    whatever MFA's transaction, or a transaction it runs inside, read first; the adapter takes the verdict as it is and
    reads no proof of its own.
  - `SessionRevokerAdapter` (IAM-3.7) calls `factorRemoved()` on the application MFA names with the removal, with the
    session the sign-in MFA names is (`CurrentSession::named()`), and returns
    `RemovalRevocation::judged()` carrying the `FactorRemoval` (its new pending credential included) as MFA's
    completion. A reset names no sign-in, so `revokeAll()` calls `factorReset()`, which ends the identity's sessions on
    every guard, through the default guard when it is a `jwt` guard and otherwise through the first `jwt` guard
    declared (`CurrentSession::identitySessions()`); it throws only when no `jwt` guard is declared.
  - `SessionTransitionAdapter` (IAM-3.8) calls `factorChanged()` on the sign-in MFA names and returns the
    `FactorChangeResult` as MFA's completion. The session is judged against the requirement `laravel-authentication`
    resolves, never MFA's `outstanding`.
  - `ProofStoreAdapter` and `FirstFactorResolverAdapter` (IAM-3.11) are `laravel-authentication`'s session proofs, read
    through `Auth::sessions()->proofs()` and `firstFactor()`. `currentSession()` is the guard's current session,
    `proofs()` its counting proofs oldest first, and the first-factor resolver its first factor. `begin()` and
    `forget()` write nothing. `record()` checks, in a transaction on the storage connection, that the proof is bound to
    the identity's current sign-in and that the session is live (`firstFactor() !== null`), and keeps only the sign-in's
    own first factor, which the session already holds; anything else throws MFA's `ProofRefusedException`.
    `laravel-authentication` is the only writer of a session's proofs. `forgetFactor()` writes nothing: MFA has deleted
    the factor and leaves its proofs out of the session it judges, and the revoker's `factorRemoved()` voids them. Both
    read only through `laravel-authentication`'s public readers (IAM-13.9) and no `@internal` class of its. MFA hands
    every call the identity, and `proofs()` the sign-in it asked `currentSession()` about; the guard's current session
    is read only to answer which sign-in is current, as MFA's contract asks, so `proofs()` of a sign-in that is no
    longer current answers none, and `record()` refuses a proof whose binding the identity it is handed does not own.
  - `SignInProofs` translates a session's recorded proofs, handed in oldest first, to MFA's proofs of the sign-in: bound
    to the identity, the application and the session's key, stamped with the identity's current verification
    generation, an external provider's proof naming its connection only under `ProviderTrust::accepted()` for the
    session's tenant, and a proof MFA cannot express left out. The proof store and the `mfa` contributor both read
    through it, so they count a session's proofs alike.
- `Mfa\MfaContextContributor` fills the `mfa` namespace of `laravel-authentication`'s authentication context (IAM-3.12,
  MFA-10.11, AUTH-11.8) with MFA's own `AuthenticationContextContributor::contributeFor()`, the one builder MFA has
  since IAM-13.4, so the keys are MFA's own eight, exactly what `Mfa::authenticationContext()` answers for the same
  session. Everything it hands MFA comes from the `ContributionSubject`: the identity the guard bound, the context's
  `application`, the session's key (`SignIn::reference()`), and the session's proofs through the subject's own
  `proofs()` and `firstFactor()`, which read the subject's session and never the request's. So a context built for
  another session, or in a queued job with no guard bound and no request, reports that session; nothing reads the
  request, a guard's state or `Auth::user()`. MFA's caller obligations are met here: the newest
  `RequirementSubject::MAX_LIMIT` proofs, reversed to oldest first, with the first factor ahead of them when it is older
  than all of them (MFA reports evidence only after exactly one first factor); and the neutral context, without asking
  MFA, for an identity that is no `MultiFactorAuthenticatable`, a subject with no session, and a session the subject's
  readers answer nothing for (pending, revoked, ended, of another guard, or no Eloquent session). MFA itself gives a
  machine and an inactive identity the neutral context. It is registered under `mfa` from the service provider's
  `booted()` callback, beside the `sso` contributor and on the same terms: only while `iam.adapters.mfa` was on when the
  binding rule read it, and only while nothing holds `mfa`, so an application's own contributor is kept (IAM-8.4).
  `ContextNamespacesCheck` requires the namespace in every application (IAM-10.2), naming `iam.adapters.mfa` when
  nothing holds it.
  - Read mode: the subject's readers choose it, as `Auth::sessions()->proofs()` does, and only while the context is
    being built. `laravel-authentication`'s guard builds `Auth::context()` once per request and keeps it
    (`HoldsAuthenticationContext`), forgetting it only when the guard binds another identity, principal or session, or
    when this process changes the session's proofs (`ContextForgetting`): a later read runs no contributor, takes no
    lock and reads nothing, and a change another process commits does not reach a context already built. A first
    build outside a transaction on the session model's connection reads the proofs plainly on the write connection; a
    first build inside one locks the session's row and reads the proofs current, so it takes the session row after
    whatever that transaction already holds (MFA's identity state and factors among them, where MFA opened it), as
    every other adapter's current read does, and reads a change committed after the transaction's first read (on
    PostgreSQL at REPEATABLE READ the lock fails to serialise instead, and the whole transaction is retried). The
    proofs are as of that build: nothing makes them agree with `laravel-authentication`'s own `amr` and `mfa` keys,
    worked out before the contributors run. A caller that needs an answer inside a transaction that is current and
    holds under the lock asks there through `Auth::sessions($guard)->proofs()` and `firstFactor()`, or through
    `Mfa::authenticationContext()`, which asks the proof store on each call, never `Auth::context()`
    (`MfaContextContributorTest` holds a context built before a transaction returned unchanged inside it).
- Refusals are thrown, never answered (IAM-8.2): MFA's `OperationRefusedException` where MFA's contract asks for it
  (`not_accepted` for the step-up and the pending completion, `not_fresh` for the factor-change gate, with
  `laravel-authentication`'s reason kept in the detail), MFA's `ProofRefusedException` from `record()`, an
  `InvalidArgumentException` for a requirement no stored proof can show, and `UnresolvedReferenceException` or
  `SessionMismatchException` wherever the identity, the session or the guard cannot be resolved. Each is thrown inside
  the transaction the member opened, so whatever it was changing rolls back.
- Every adapter runs inside MFA's or `laravel-authentication`'s transaction on the one storage connection
  (`storage-and-transactions.md`), and the lock order is the identity's state, then its factors, before any row of
  `laravel-authentication`'s:
  - MFA takes the identity's state first and its factors second, in one transaction, for a verification, a factor
    change, a removal and a reset.
  - The session row is taken after both: by the proof store's read inside MFA's transaction, by the factor-change
    gate, by the reauthenticator and by the freshness gate when MFA's own factor-change gate asks them there, by the
    step-up and the pending completion, which write it last, and by the revoker. A current read takes the session's
    row, then its proofs (on MySQL and MariaDB under a shared lock, which at REPEATABLE READ also holds the gaps on
    either side of them). A removal goes on from there: the current session's row, then its proofs, then, in the
    revoker's `factorRemoved()`, the rows of the identity's other sessions, which it ends. That is
    `laravel-authentication`'s chosen order, and it takes another session's row after the current session's, not
    before.
  - Every other row of MFA's taken in the same transaction (the challenge a verification consumes, an enrolment, a
    passkey association) is the identity's own, which nothing takes without the identity's state; MFA's counters of
    attempts are kept outside the transaction.
  - `laravel-authentication` alone (a step-up, a refresh, a bulk revocation) takes the session row and nothing of
    MFA's.
  - So no two transactions can each hold a row the other waits on, but for one case `laravel-authentication` keeps by
    design: on MySQL and MariaDB at REPEATABLE READ, a removal holding the gaps around the current session's proofs
    while it waits on a neighbouring session's row, and a step-up or reauthentication of that session holding its row
    while its proof waits on one of those gaps, deadlock. The database fails one side, and the caller rolls back its
    whole transaction and retries, as the Concurrency case under [Failure / Edge Cases](#failure--edge-cases) sets
    out. In a verification the proof read takes the session row before the challenge is consumed, which is safe for
    the same reason as the rest: a transaction that holds a challenge holds the identity's state.
  - The adapters that only read (the policy, the requirement check, the pending session resolver) take no lock of their
    own, and nor does the freshness gate asked outside a transaction; asked inside one, its current read takes the
    session's row after MFA's locks, and a removal through MFA's own gate then goes on to take the identity's other
    sessions' rows.

## Success Path

- Install the package with the switch on (the default) and declare each MFA application as a `jwt` guard of the same
  name in `auth.guards`. MFA names its application after the guard it reads the caller through, which is the default
  guard unless it is given another.
- A sign-in: `Auth::sessions()->signIn()` asks the policy adapter, MFA composes the requirement, and the session starts
  active or pending. MFA's `verify()` on a pending session resolves it through the pending session resolver, and the
  completion calls `satisfy()` as MFA's last write; the session activates, and the guard is bound once MFA commits.
- A step-up with a stateless guard (the reproduction of sinemacula/laravel-iam#3): a bearer token's session verifies a
  further factor on one request, the step-up adapter records it on the session, and the next request with the same
  token meets the requirement, with no Laravel session started; another session of the same person does not. The next
  request's `Auth::context()` reports `mfa.accepted`, from the same session's proofs.
- A factor change: MFA locks the identity's state and factors, the gate locks the session row through `factorChange()`
  and allows the change on a fresh step-up (or, for the first additional factor, a fresh reauthentication), and the
  session transition judges the session again once the change is made.
- A removal: the gate allows it on a step-up made with another factor, the removed factor's proofs stop counting as
  soon as MFA deletes it, `factorRemoved()` ends every other session and voids the current session's proofs made with
  the factor, and the removal result carries any new pending credential back to the caller, with the requirement
  outstanding whenever the session was returned to pending. A reset ends every session.

## Failure / Edge Cases

- `begin()` is a no-op, not a check: `laravel-authentication` fires `Login` on every activation and refresh before the
  guard is bound, and MFA's `BeginSignInOnLogin` calls `begin()` with a fresh id of its own, so a check would break
  every sign-in and refresh. `forget()` is a no-op because `laravel-authentication` revokes the session, or forgets the
  guard's binding, before `Logout` reaches MFA, and whether a session ends is its decision.
- A guard holding no session of the identity answers `currentSession() === null` and `proofs() === []`, as MFA's
  contract asks and its kit checks after a void, and as it does once `laravel-authentication` signs the session out;
  an application that is no session guard throws.
- `record()` refuses everything but the sign-in's own first factor, so an application that rebinds `StepUp` or
  `PendingCompletion` back to MFA's `ProofStoreCompletion` has every verification refused; rebind both or neither.
- `VerificationGeneration::advance()` on its own no longer voids anything: the proofs are stamped with the current
  generation when read. Voiding goes through `laravel-authentication` (`factorReset()`, `factorRemoved()`, a
  revocation).
- MFA's `ProofStoreTests` kit runs through its hooks for a store whose proofs and sign-ins the authentication layer
  alone writes. `laravel-authentication` records a session's first factor only when it signs the session in, so each
  check's sign-in is signed in through it with the guard no longer acting on it: the store holds no sign-in of the
  identity until the check arranges its password first factor, which the guard then acts on, as the bearer request
  after a sign-in does, and which the store keeps when the check's proof is recorded through it. A further factor is
  recorded through `stepUp()`, with a factor enrolled in MFA's factor table; a sign-in ends through `signOut()`, and a
  void is `factorReset()`.
- A step-up an application hands `laravel-authentication` itself counts as recorded, whatever factor it names.
- MFA's test helper `InteractsWithMfa::actingAsVerified()` (`Testing\VerifiedSignIn`) cannot record through this store:
  by default it records its further proof through `record()`, which refuses it. MFA closed that member gap with a
  recorder hook in `VerifiedSignIn` (`Testing\Contracts\VerifiedSignInRecorder`, which the helper uses whenever it is
  bound), and this package binds it, under the capability's switch and outside tests too, since MFA reads it only from
  its helper, to `Testing\VerifiedSignInRecorderAdapter`. Its `begin()` is handed the time the helper makes its proofs
  at, and starts a session for the identity through `laravel-authentication`'s `start()` from a password first factor
  (`FirstFactor` on the `password` channel with the `pwd` value, the `password` method), as an application that checked
  a password itself starts one, with the clock held at that time while it starts, so the session's first factor is the
  password proof MFA's helper would otherwise record, made at that time, and the helper keeps it. The identity's
  stored credentials are never read or written. The start runs in `CrossMemberTransaction` from `CallerSignIn`'s
  client; a refused sign-in, or one pending on anything but a further factor, throws a `LogicException` naming the
  reason inside it, so it leaves nothing. A session that activates is acted on, as `actingOnSession()` does. One left
  pending on a further factor (a person who holds a confirmed factor, under an application requiring one at sign-in,
  the person the helper enrolled one for included, the next time) is kept pending, with its pending credential held by
  the recorder until the helper's further proof completes it; MFA's contract lets a recorder complete a pending
  sign-in with that proof, as long as the sign-in begun is the store's current one once it is recorded. That
  credential is the recorder's only state, forgotten by the next `begin()`, and the binding is transient, so it never
  outlives the one sign-in MFA's helper resolved the recorder for. Its `factorReference()` names the real factor the
  helper's further proof (MFA's `Testing\LevelEvidence`) is made with: a confirmed factor of the level's type the
  identity holds, or one enrolled for it (`Testing\FixtureFactors`: an email factor for AAL1, an authenticator app for
  AAL2, a passkey for AAL3). Its `record()` keeps the sign-in's own first factor (through this store's `record()` for
  an active session, and, for the pending session it began, when it is a password), and records the further proof as
  it is, at the proof's own time, with the clock held there, so `laravel-authentication` judges it then: an active
  session is stepped up with it, bound for a step-up (`VerifiedSession::stepUp()`), and the pending one is completed
  with it (`CallerCompletion::satisfy()`) and then acted on, each flagged multifactor as MFA's own acceptance would
  flag it. A completion that leaves the sign-in pending all the same throws a `LogicException` and rolls back. A proof
  bound neither to the pending sign-in it began nor to the identity's current sign-in is refused with MFA's
  `ProofRefusedException`. MFA's helper reads the proofs back and throws unless its route gate would read the session
  at exactly the level. `actingOnVerifiedSession($session, $level)` verifies a session the test already holds the same
  way, with the further proof made now, so a freshness test verifies the session and then moves the clock on; without
  the recorder bound, the refusal `actingAsVerified()` meets names that helper. The suite-wide `actingAsCaller()`
  (IAM-12.2) builds on `actingOnVerifiedSession()`; the application's side of all three is in `docs/guides/testing.md`.
- `actingAsCaller($identity, $principal, $tenant, $guard, $session, $verified, $scopes)` is the testing helper's one
  core method, taking plain values only. A person is signed in for real (`Testing\CallerSignIn`, internal) and the test
  acts on the new session, so every adapter reads the caller from the session `laravel-authentication` wrote, never from
  a stub: the principal and the tenant are chosen through the `SignInContext`, so the session records the tenant MFA's
  active tenant resolver reads, and the test then acts in it so `Auth::tenant()` answers it too. How the person signs in
  is one `Testing\CallerSession` value: `started()` through `start()` on the `unknown` channel, so MFA judges
  no first factor and no level can follow (refused before anything is written); `signedIn()` through `signIn()` with the
  credentials, which must sign in the identity given; or `throughSso()` with SSO's own `Sessions\Provenance`, signed in
  as `Iam::signIns()` signs in an admitted redemption (`AdmittedRedemptions` recorded for the call and forgotten after
  it, `signInExternally()` handed `ExternalResults::from()`'s result, so the session records the provenance as its
  provider context). The three are one value rather than three arguments because they exclude each other, and because a
  method taking eight arguments would not stay one readable call. Every sign-in runs in `CrossMemberTransaction` and
  must activate the very identity acted as, or a `LogicException` names the reason inside that transaction, so whatever
  the sign-in wrote rolls back with it; a level is then verified through `actingOnVerifiedSession()`. A machine is acted
  as without a session (`actingAsIdentity()`), with its scopes. A sign-in left pending on a further factor (an
  application requiring one of a person who already holds a confirmed factor: a person seeded with one, or one a level
  was verified for in an earlier call) is completed, not refused, so the same person can be acted as twice and a test of
  a holder's factors can use the helper: `Testing\CallerCompletion` reads the pending context back from the credential
  through `PendingSessionResolverAdapter::fromCredential()`, makes a proof of the level's evidence (an authenticator
  app's without a level) with a confirmed factor of its type the person holds (enrolling one when they hold none), bound
  to the pending session for sign-in and flagged multifactor as MFA's acceptance would flag it from the pending first
  factor and the proof alone, and hands it to `PendingCompletionAdapter::complete()` inside the same transaction, as
  MFA's verification would. A sign-in still pending after that (on a choice of principal) is refused, naming what it
  waits on. A `started()` session is never completed: its first factor is on the `unknown` channel, so MFA accepts no
  further proof after it, and the refusal says to sign in with `signedIn()` or `throughSso()`.
- A minimum assurance level in MFA's freshness configuration (for an operation the freshness gate is asked about, or
  for `mfa.add_factor`, `mfa.remove_factor` or `mfa.generate_recovery_codes`) throws an `InvalidArgumentException`
  whenever it is asked, as no stored proof records a level. Configure the operation without one, or bind a gate of your
  own.
- An additional verification in the freshness gate counts only a further factor or a recovery code, which is stricter
  than MFA's own gate (where a multifactor first factor alone counts). A setting in `laravel-authentication` that also
  takes a first factor and asks for no flag adds nothing MFA can express, so `requirement()` answers the caller's
  requirement alone, or `null`, while `isFresh()` still enforces the setting.
- A further proof is flagged multifactor only as its own evidence, so after a sign-in with a multi-factor
  authenticator (a passkey that verified the person) a weaker step-up is not flagged. `laravel-authentication` keeps no
  evaluation on a first factor, so it does not count that sign-in as fresh multifactor authentication either: a
  requirement for recent multifactor authentication takes a step-up that is itself multifactor.
- Every refusal `stepUp()` and `satisfy()` answer with is MFA's `not_accepted`. MFA lets an active caller ask for a
  `sign_in` verification, which `laravel-authentication`'s `stepUp()` refuses as `proof_invalid`, so with the adapter
  bound that verification fails where MFA's default would have recorded it. `laravel-authentication`'s own report of
  the refusal, dispatched inside MFA's transaction, which the adapter's throw rolls back, is recorded in the audit trail
  under its own reason once that transaction has ended (see `audit-mapping.md`).
- Every refusal `factorChange()` answers with, a session no longer live included, is MFA's `not_fresh`. A removal never
  counts a step-up made with the factor removed, even for the identity's only confirmed factor, and the first
  additional factor takes `laravel-authentication`'s reauthentication window (`first_additional_factor`, fifteen
  minutes by default) rather than MFA's five minutes.
- The freshness gate and a removal use the application MFA hands them: one that is not a `jwt` guard throws and rolls
  back. The pending session resolver's `fromRequest()` uses the default guard, which `ApplicationResolverAdapter` names
  too when MFA reads a caller through no guard of its own, so such a caller is on the guard its pending session was read
  from. A caller read through another guard is named after that guard, except a pending one, which MFA reads on the
  default guard whatever guard it is given (member gap: MFA hands its pending session resolver the guard). A reset is
  made wherever it is asked for (an admin panel's session guard, a console command, a queued job): it goes through the
  first `jwt` guard declared when the default guard is not one, and the guard it goes through forgets its binding to the
  identity once the reset commits.
- A pending session holding more than `MAX_LIMIT - 1` further proofs hands MFA only the newest; a proof the translator
  cannot build makes the pending resolution throw, while the proof store leaves such a proof out of the count. Both
  fail closed.
- Concurrency:
  - MFA opens the transaction of each of its changes itself (a verification, a factor change, a removal, a reset), so
    those flows cannot be wrapped (IAM-11.2): never run one inside `Iam::transaction()` or any transaction the
    application opens. MFA's own transaction never retries, and only the outermost transaction can be retried, so the
    caller retries the request instead.
  - At REPEATABLE READ on PostgreSQL a change that waited on a row another transaction changed fails to serialise. MFA's
    own transaction never retries, so the failure reaches the caller as Laravel's `DeadlockException`, and the request
    made again resumes against what the other committed.
  - At REPEATABLE READ on MySQL MFA's own transaction fixes its snapshot only once it holds the identity's state, so it
    reads what was committed while it waited. Wrapped in another transaction, it would not: the plain read MFA makes
    before it takes its locks fixes the enclosing transaction's snapshot before the wait. The freshness judgements that
    decide a change no longer read that snapshot: `factorChange()` judges the session's proofs as committed under the
    session's lock, as `proofs()` and `firstFactor()` read them, and so do the freshness gate and the reauthenticator
    asked inside MFA's transaction. So a step-up voided while a wrapped change waited never allows it:
    `laravel-authentication`'s gate refuses it (`step_up_required`), and this package's gate passes that refusal on as
    MFA's `not_fresh`. Wrapping stays unsupported, for the reasons above, not because a wrapped change could go ahead
    on a voided step-up.
  - On MySQL and MariaDB at REPEATABLE READ the gate's current read holds the gaps on either side of the session's
    proofs until MFA's transaction ends, and a removal then ends the identity's other sessions (`factorRemoved()`). A
    step-up or reauthentication of a neighbouring session of the same identity (one whose proofs border these) that
    holds that session's row while its proof waits on a gap, and the removal waiting on that row, deadlock. The
    database fails one side, with nothing half-written: usually the neighbour's, the smaller transaction, and the
    other goes ahead. What the failed side throws depends on where its statement ran. Inside a transaction someone
    else opened it is Laravel's `DeadlockException`: MFA's change (`factorRemoved()` runs in a savepoint inside MFA's
    transaction), or a step-up or reauthentication the application makes inside a transaction of its own. Made
    directly through `Auth::sessions()` (`reauthenticate()`, `stepUp()`) with no transaction open,
    `laravel-authentication`'s own transaction is the outermost, and Laravel rethrows the database's `QueryException`
    (SQLSTATE 40001, MySQL error 1213), which its concurrency detection recognises all the same. So a caller detects a
    concurrency failure rather than catching one exception class: with Laravel's `ConcurrencyErrorDetector` (as
    `DetectsConcurrencyErrors` asks it), walking the exception's previous ones as `Iam::transaction()` does, or by
    making the step-up or reauthentication inside `Iam::transaction()`, which retries it whole, against the removal
    that ended the session. It then rolls back its whole transaction and retries (the request, for MFA's change).
    `laravel-authentication` keeps that order by design, as two removals from two sessions of one identity could
    already deadlock on their rows the same way. A password reset run inside a caller's transaction likewise surfaces
    a deadlock as `DeadlockException`, with the caller's level restored, a concurrency failure `Iam::transaction()`
    retries whole when it opened the outermost transaction.
  - At READ COMMITTED, on both engines, the waiting side resumes against what the other committed.
- One requirement judgement reads the generation and nothing else (the proofs are the subject's, read by
  `laravel-authentication` in its one bounded query); one policy question reads the generation and what MFA composes
  its answer from. `benchmarks/Mfa/RequirementCheckBench.php` times a judgement with one further proof and with as many
  as one read returns.

## Implementation Anchors

- `src/Mfa/MfaSeams.php`: `seams()`, `SWITCH`; `src/IamServiceProvider.php`: `seamProviders()`; `config/iam.php`:
  `adapters.mfa`.
- `src/Mfa/CurrentSession.php`: `named()`, `of()`, `current()`, `held()`, `identity()`, `caller()`, `defaultGuard()`,
  `guard()`, `sessions()`, `identitySessions()`, `isInTransaction()`.
- `src/Mfa/Translation/SignIn.php` (`UNNAMED`, `reference()`, `binding()`), `ChannelTranslator.php`,
  `ProofTranslator.php` (`toMfa()`, `toResult()`), `RequirementTranslator.php` (`toMfa()`,
  `toAuthentication()`, `evaluation()`, `toFreshnessParts()`, `toFreshness()`, `fromFreshness()`),
  `ChangeTranslator.php`, `ClientTranslator.php` (`toAuthentication()`, `toMfa()`, `unknown()`).
- `src/Mfa/AdditionalFactorPolicyAdapter.php`, `RequirementCheckAdapter.php`, `PendingSessionResolverAdapter.php`
  (`fromRequest()`, `revalidate()`, `fromCredential()`), `PendingCompletionAdapter.php`, `StepUpAdapter.php`, `ReauthenticatorAdapter.php`,
  `FreshnessGateAdapter.php` (`heldUntil()`), `FactorChangeGateAdapter.php` (`allowedUntil()`),
  `SessionRevokerAdapter.php`, `SessionTransitionAdapter.php`, `ProofStoreAdapter.php` (`firstFactor()`),
  `FirstFactorResolverAdapter.php`, `SignInProofs.php` (`of()`, `holdsAFirstFactor()`, `factorReference()`).
- `src/Mfa/MfaContextContributor.php` (`contribute()`); `src/IamServiceProvider.php`: `registerContextContributors()`,
  `registerContributor()`; `src/Checks/ContextNamespacesCheck.php`.
- `src/Testing/Concerns/InteractsWithIam.php` (`actingOnVerifiedSession()`), `src/Testing/VerifiedSession.php`
  (`verify()`, `stepUp()`), `src/Testing/VerifiedSignInRecorderAdapter.php` (`begin()`, `record()`,
  `factorReference()`), `src/Testing/FixtureFactors.php` (`held()`), `src/Testing/CallerCompletion.php` (`complete()`,
  `satisfy()`).
- `src/Exceptions/UnresolvedReferenceException.php` (`forGuard()`, `forSession()`, `forIdentity()`, `forMfaIdentity()`),
  `src/Exceptions/Enums/ReferenceKind.php`, `src/Exceptions/SessionMismatchException.php`.

## Authoritative Tests

- `tests/Feature/Mfa/MfaSeamsTest.php` `testEveryAdapterIsBoundOverItsMembersDefaultInEveryProviderOrder`,
  `testAnApplicationBindingMadeBeforeAnyProviderRegistersIsKept`,
  `testAnApplicationBindingMadeOnceEveryProviderHasRegisteredWins`, `testTheSwitchOffBindsNothing`,
  `testTheSwitchIsReadLeniently`, `testEveryBindingIsTransientOverItsMembersDefault`
- `tests/Integration/Mfa/CurrentSessionTest.php`
- `tests/Unit/Mfa/Translation/*Test.php`, notably `ProofTranslatorTest`
  `testAnExternalReauthenticationIsAFirstFactorReauthenticationOnTheProvidersChannel` and `RequirementTranslatorTest`
  `testEveryLevelCrossesAsItselfAndUnclassifiedIsNone`, `testAPartNoFreshnessCanHoldIsRefused`,
  `testARequirementAskedAsAWholeIsOneFreshnessRequirement`
- `tests/Unit/Exceptions/UnresolvedReferenceExceptionTest.php`, `SessionMismatchExceptionTest.php`,
  `Enums/ReferenceKindTest.php`
- The adapter tests in `tests/Integration/Mfa`, each over MFA's contract kit where one exists
  (`PendingSessionResolverTests`, `PendingCompletionTests`, `StepUpTests`, `ReauthenticatorTests`,
  `FreshnessGateTests`, `FactorChangeGateTests`, `SessionRevokerTests`, `SessionTransitionTests`, `ProofStoreTests`,
  `FirstFactorResolverTests`, every check run), with their own cases on MySQL and
  PostgreSQL at READ COMMITTED and REPEATABLE READ:
  - lock order: `StepUpAdapterTest` and `ReauthenticatorAdapterTest` (`testTheSessionRowIsTheOnlyLockItTakes`),
    `FreshnessGateAdapterTest` (`testInsideMfasTransactionItLocksTheSessionRowLast`),
    `PendingCompletionAdapterTest` (`testTheSessionIsLockedAfterMfasLocks`), `FactorChangeGateAdapterTest`
    (`testTheSessionsRowIsHeldUntilTheCallersTransactionEnds`,
    `testEnrollingAFurtherFactorThroughMfaIsGatedAfterMfasLocks`), `SessionRevokerAdapterTest`
    (`testRemovingAFactorThroughMfaEndsTheOtherSessionsLast`), `SessionTransitionAdapterTest`
    (`testConfirmingAnEnrolmentJudgesTheSessionLastThroughMfa`), `ProofStoreAdapterTest`
    (`testRecordingLocksTheSessionRowLastInTheCallersTransaction`, `testASessionRevokedConcurrentlyIsReadCurrent`),
    `FirstFactorResolverAdapterTest` (`testResolvingLocksTheSessionRowLastInTheCallersTransaction`);
  - no lock taken: `RequirementCheckAdapterTest` (`testJudgingTheSessionTakesNoMfaLock`),
    `PendingSessionResolverAdapterTest` (`testResolvingTakesNoLockAndWritesNothing`), `FreshnessGateAdapterTest` and
    `ReauthenticatorAdapterTest` (`testOutsideATransactionItAsksPlainlyAndTakesNoLock`);
  - read mode: `FreshnessGateAdapterTest` and `ReauthenticatorAdapterTest`
    (`testOutsideATransactionItAsksPlainlyAndTakesNoLock`, `testInsideATransactionItAsksCurrent`), and
    `FreshnessReadModeTest` from where MFA asks each, every adapter bound: plainly from its route gate
    (`testMfasRouteGateAsksTheFreshnessGatePlainly`) and `Mfa::isFresh()`
    (`testMfasFreshnessQuestionAsksTheFreshnessGatePlainly`), current from its own factor-change gate inside its
    transaction (`testMfasOwnFactorChangeGateAsksTheFreshnessGateCurrent`,
    `testMfasOwnFactorChangeGateAsksTheReauthenticatorCurrent`), each judgement asked by the adapter named, for MFA's
    operation (or `first_additional_factor`), never by `laravel-authentication`'s own gate behind this package's,
    which asks current too, and no `LogicException` on either path;
  - current reads, inside a caller's transaction that read before another connection committed a change, at READ
    COMMITTED and REPEATABLE READ (on PostgreSQL's REPEATABLE READ after a failure to serialise and a retry):
    `FreshnessGateAdapterTest` (`testAStepUpVoidedAfterTheTransactionsFirstReadIsNotFresh`,
    `testAStepUpMadeAfterTheTransactionsFirstReadIsFresh`), `ReauthenticatorAdapterTest`
    (`testAReauthenticationMadeAfterTheTransactionsFirstReadIsAnswered`), `FactorChangeGateAdapterTest`
    (`testAStepUpVoidedAfterTheTransactionsFirstReadNeverAllowsAChange`,
    `testAStepUpMadeAfterTheTransactionsFirstReadAllowsAChange`);
  - rollback: `AdditionalFactorPolicyAdapterTest` (`testARefusalRollsBackTheProofAtEachIsolationLevel`),
    `PendingCompletionAdapterTest` (`testARollbackLeavesTheSessionPending`, `testAFailedCommitNeverAnswersTheSignIn`),
    `FactorChangeGateAdapterTest` (`testAChangeWithoutTheIdentitysSessionIsRefusedAndRollsBack`),
    `SessionRevokerAdapterTest` (`testARemovalFromASignInThatIsNoSessionOfTheIdentitysIsRefusedAndRollsBack`),
    `SessionTransitionAdapterTest` (`testAChangeOnASignInThatIsNoSessionOfTheIdentitysIsRefusedAndRollsBack`),
    `ProofStoreAdapterTest` (`testARefusalRollsTheCallersTransactionBack`), `FirstFactorResolverAdapterTest`
    (`testAnUnresolvedSignInRollsTheCallersTransactionBack`).
- `tests/Integration/Mfa/CurrentSessionTest.php` `testTheNamedSignInIsResolvedWhateverTheGuardHolds`,
  `testASignInThatIsNoSessionOfTheIdentitysOnTheGuardResolvesNone`; `StepUpAdapterTest.php`
  `testTheBoundSessionIsSteppedUpWhateverTheGuardHolds`, `testAProofOfAnotherOfTheIdentitysSessionsStepsThatSessionUp`;
  `SessionRevokerAdapterTest.php` `testARemovalFromTheNamedSignInIsMadeWhateverTheGuardHolds`;
  `SessionTransitionAdapterTest.php` `testTheNamedSignInIsJudgedWhateverTheGuardHolds`;
  `FactorChangeGateAdapterTest.php` `testAChangeIsGatedOnTheNamedSignInWhateverTheGuardHolds`: the sign-in MFA names
  is acted on whatever the guard holds
- `tests/Integration/Mfa/PendingCompletionAdapterTest.php` `testACookieGuardsSameSiteCompletionIsSatisfied`,
  `testACookieGuardsCrossSiteCompletionIsRefused`, `testTheActivatedSessionsLastUseIsTheCallersClient`,
  `testACallerWithNoPendingSessionIsRefused`: the pending completion's caller, its client judged by a cookie guard's
  same-site check (a same-site one activates the session, a cross-site one is refused inside MFA's transaction and
  rolls back) and recorded as the session's last use, and a caller with no pending session refused; MFA's
  `PendingCompletionTests` run on a cookie guard with a same-site caller
- `tests/Integration/Mfa/FactorRemovalTest.php` `testTheOutstandingRequirementAgreesWithTheJudgedSession`,
  `testTheRemovedFactorsProofNoLongerCountsOnTheSession`, `testTheRemovedFactorStopsCountingInsideMfasTransaction`: a
  removal through MFA with every adapter bound reports a requirement outstanding exactly when `laravel-authentication`
  returned the session to pending, and the removed factor's proof stops counting;
  `tests/Integration/Mfa/SessionRevokerAdapterTest.php`
  `testAResetMadeWhereTheDefaultGuardHoldsNoSessionsEndsEverySession`,
  `testAResetGoesThroughTheDefaultGuardWhenItHoldsSessions`, `testAResetWithNoSessionGuardDeclaredIsUnresolved`
- `tests/Integration/Mfa/FactorChangeLockOrderTest.php` `testAStepUpWaitingOnARemovalResumesAgainstIt`,
  `testARemovalWaitingOnAStepUpResumesAgainstIt`, `testAFactorChangeWaitingOnARemovalResumesAgainstIt`,
  `testARemovalThatFailsToSerialiseIsMadeWhenTheCallerRetriesTheRequest`,
  `testAWrappedRemovalIsNeverAllowedOnAStepUpVoidedWhileItWaited`,
  `testEachChangeTakesTheIdentityStateAndFactorsBeforeTheSessionRow`,
  `testARemovalTakesTheCurrentSessionAndItsProofsBeforeTheIdentitysOtherSessions` (the identity's other sessions'
  rows taken after the current session's row and its proofs), every adapter bound by the binding rule (the
  wrapped removal refused by `laravel-authentication`'s own gate, `step_up_required`, on MySQL and PostgreSQL at READ
  COMMITTED and REPEATABLE READ); `testANeighbouringProofDeadlockedWithARemovalFailsAsAConcurrencyFailure` (on MySQL
  at REPEATABLE READ, a neighbouring session's step-up or reauthentication fails with nothing of it written, as a
  `QueryException` made directly, a `DeadlockException` inside the caller's transaction, both recognised as
  concurrency failures, and retried by `Iam::transaction()` against the removal); `FactorChangeGateAdapterTest`
  `testAChangeIsJudgedOnLaravelAuthenticationsVerdictAlone` (one read of the session's proofs, the verdict's)
- `tests/Unit/Mfa/Translation/ProofTranslatorTest.php` `testTheProofIsMultifactorOnlyWhenItRefreshesTheEvidence`;
  `tests/Integration/Mfa/StepUpAdapterTest.php` `testTheProofIsRecordedMultifactorOnlyWhenItRefreshesTheEvidence`
  (accepted, at the proof's time, multifactor exactly as `refreshesMultifactor` says, whatever the whole session's
  evaluation says);
  `tests/Integration/Mfa/MultifactorEvidenceTest.php` `testAFreshWeakerProofNeverRefreshesAnOldMultifactorOne` (a
  fresh email code after an old authenticator app code is not fresh multifactor authentication, before or after the
  authenticator app is removed, as MFA's own check judges); `PendingCompletionAdapterTest`
  `testEachProofIsRecordedWithItsOwnEvaluation`
- `tests/Integration/Mfa/StatelessVerificationTest.php` `testAVerificationCountsOnTheNextRequestWithTheSameToken`
- `tests/Integration/Mfa/MfaContextContributorTest.php` `testTheRequestsContextIsMfasOwnView`,
  `testAnotherSessionsContextIsItsOwn`, `testAJobsContextIsTheNamedSessions`, `testASessionNoLongerLiveIsNeutral`,
  `testNoSessionAndAnIdentityThatCannotHoldFactorsAreNeutral`, `testAFirstFactorOlderThanEveryProofReadStillCounts`,
  `testASessionWhoseFirstFactorNoLongerCountsReportsNoEvidence`, `testTheAgeIsTheNewestVerifications`,
  `testProofsMadeAtOneInstantKeepTheirOrder`, `testInsideATransactionTheProofsAreReadCurrent`;
  `tests/Integration/Mfa/SignInProofsTest.php` `testProofsAreKeptInTheOrderHandedIn`,
  `testAFactorIsNamedByItsIdentifierAsText`
- `tests/Feature/Sso/ContextContributorRegistrationTest.php` `testTheContributorsAreRegisteredInEveryProviderOrder`,
  `testTheMfaSwitchOffRegistersNothingUnderMfa`, `testTheMfaSwitchTurnedOffLaterLeavesTheBindingsAndTheContributorOn`,
  `testAnApplicationsEarlierMfaContributorIsKept`, `testAnApplicationsLaterMfaContributorIsKept`;
  `tests/Feature/IamServiceProviderTest.php` `testTheContextContributorsAreRegisteredOnceBooted`;
  `tests/Feature/Checks/ContextNamespacesCheckTest.php` `testAnMfaNamespaceNobodyRegisteredFails`
- the caller handed as plain values, a request bound beside each core call never read
  (`tests/Concerns/BindsStrayRequests.php`): `PendingSessionResolverAdapterTest` (`testTheContextKeepsItsCredential`,
  `testRevalidatingReadsTheSessionAsItStandsNow`, `testRevalidatingReadsTheContextsApplication`,
  `testAContextWithoutACredentialNoLongerStands`, `testASessionThatEndedNoLongerStands`,
  `testAnotherSessionNoLongerStands`, `testOnlyTheRequestHandedInIsRead`, `testRevalidatingReadsNoBoundRequest`,
  `testRevalidatingWithoutASessionServiceIsRefused`, `testACredentialHandedInIsReadOnTheApplicationsGuard`,
  `testACredentialHandedInThatNamesNoSessionIsNone`), `PendingCompletionAdapterTest`
  (`testAnotherPendingSessionsCredentialIsRefused`, `testWithoutAPendingCredentialNothingIsSatisfied`,
  `testTheHandedContextIsSatisfiedWhateverTheRequestCarries`, `testWithoutACredentialTheBoundRequestIsNotReadInstead`,
  `testACookieGuardsCrossSiteCompletionIsRefused`),
  `StepUpAdapterTest` (`testOnlyAnActiveCallersSessionIsSteppedUp`, `testTheCallersClientDescribesTheStepUp`,
  `testACallerThatIsNotTheSessionsIsRefusedInsideTheTransaction`,
  `testTheCallersApplicationIsSteppedUpWhateverTheDefaultGuard`), `FreshnessGateAdapterTest`
  (`testTheCallersApplicationIsAsked`, `testOnlyAnActiveCallersOwnSessionCanBeFresh`), `SessionRevokerAdapterTest`
  (`testARemovalIsMadeOnTheApplicationItNames`); `tests/Unit/Mfa/Translation/ClientTranslatorTest.php`
- `tests/Performance/Mfa/RequirementQueryBudgetTest.php`; `benchmarks/Mfa/RequirementCheckBench.php`
- `tests/Integration/Testing/VerifiedSignInRecorderAdapterTest.php` `testMfasHelperVerifiesThePersonAtExactlyTheLevel`,
  `testAPersonWhoMustVerifyAtSignInIsVerifiedThroughThePendingSignIn`,
  `testTheSessionHoldsThePasswordAndAFurtherProofMadeAtTheTimeAsked`, `testAPendingSignInIsCompletedAtTheTimeAsked`,
  `testThePersonsStoredCredentialsAreUntouched`, `testAVerifiedPersonCanBeVerifiedAgain`,
  `testARefusedSignInIsReportedAndLeavesNothing`, `testAFurtherProofThatLeavesTheSignInPendingIsRefusedAndRolledBack`,
  `testTheActiveSignInsOwnFirstFactorIsKeptAndAnotherRefused`,
  `testThePendingSignInsOwnPasswordIsKeptAndAnotherFirstFactorRefused`,
  `testAProofBoundToAnotherSignInOrIdentityIsRefused`, `testOnlyThePendingSignInBegunLastIsCompletedForItsOwnIdentity`
- `tests/Feature/Testing/InteractsWithIamTest.php` `testMfasActingAsVerifiedIsRefusedByThisPackagesStoreWithoutItsRecorder`,
  `testAVerifiedSessionPassesMfasRouteGate`, `testTheFurtherProofIsRecordedWithAFactorThePersonHolds`,
  `testAPersonActsOnASessionTheySignedInTo`, `testTheTenantIsTheSessionsAndTheGuards`,
  `testAVerifiedCallerPassesMfasRouteGate`, `testEveryPartComposesOnOneSession`,
  `testAnSsoCallerCarriesTheProvenanceOnTheSession`, `testALevelForAStartedSessionIsRefusedBeforeTheCallerSignsIn`,
  `testAMachineActsWithoutASessionLimitedToItsScopes`

## Change Triggers

Update this note when:

- a member renames, adds or removes one of the seams in the table, or changes a default's class or binding style;
- `laravel-authentication` gains a public write path for a session's proofs, or a single-factor void (the proof store
  could then record and forget, and its kit could run without its hooks);
- MFA stops leaving a removed factor's proofs out of the session it judges, or changes what a proof's reference names;
- `laravel-mfa`'s `VerifiedSignIn` changes its recorder contract (the sequence of proofs, or whether a pending sign-in
  may be completed with the further proof), or changes `Testing\LevelEvidence` (`actingOnVerifiedSession()` and
  `actingAsCaller()` prove with it too, and `VerifiedSession::AMR` holds the `amr` of each of its methods);
- `laravel-authentication` changes how `start()` times a session's first factor, or how a step-up or a pending
  completion judges a proof's time or a pending credential's expiry (`VerifiedSignInRecorderAdapter` holds the clock at
  the helper's time for each);
- `laravel-authentication` gains a public read of a session of a guard by the identity and its id
  (`CurrentSession::named()` then reads through it in place of the identity's `sessions()` relation), or either member
  changes what its `ClientContext` carries (`ClientTranslator` follows);
- MFA's caller starts carrying its sign-in (the freshness gate and the reauthenticator then read it without the
  guard);
- MFA hands its pending session resolver the guard, or stops handing the application resolver the guard it reads a
  caller or a sign-in through (`codes-delivery-and-passkeys.md`);
- either member changes a value both spell the same, adds a proof kind, channel, level or requirement part, or changes
  the lock order of its transactions;
- `laravel-authentication`'s freshness requirement gains an additional verification or a level, or the mapping of
  refusals to MFA's failure reasons is decided differently;
- IAM-5.1 (whether a provider's authentication counts) is settled, which may change what the requirement check reads;
- `laravel-authentication`'s `factorChange()` stops judging the session's proofs as committed under the session's lock
  (the gate would need its own current read back), its freshness policy changes where it may be asked current, what a
  current read locks or in what order, or its freshness starts to read a first factor's evaluation;
- MFA asks the freshness gate or the reauthenticator inside a transaction where it does not act on the answer, or acts
  on it atomically outside one (the read mode `CurrentSession::isInTransaction()` decides would then be wrong);
- MFA changes what `VerificationResult::$refreshesMultifactor` or `Evaluation::$multifactorAt` says, or starts handing
  over a proof it has not accepted after the session's first factor.
- MFA changes what `contributeFor()` asks of its caller, or its keys, or `laravel-authentication` changes what
  `ContributionSubject::proofs()` and `firstFactor()` read, their read mode or their limit (`MfaContextContributor`
  follows), or stops keeping the context a guard built or changes what forgets it (the read mode the guide states
  follows);
- `laravel-authentication`'s sign-in starts completing a pending session for a test (`actingAsCaller()` could then
  complete a pending one rather than refuse it), or `CallerSession::started()` comes to name a channel MFA can judge (it
  could then verify a started session).
