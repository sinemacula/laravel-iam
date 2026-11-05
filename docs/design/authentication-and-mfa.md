# Authentication and MFA

## Purpose

This note describes how the package joins `laravel-authentication` and `laravel-mfa` (IAM-3.1 to IAM-3.8, IAM-3.11,
IAM-3.14 and IAM-5.2). It covers the twelve seams `Mfa\MfaSeams` binds, how an MFA sign-in is resolved to one of
`laravel-authentication`'s sessions, how the members' value types are translated, how each adapter answers and
refuses, and the transactions and lock order the adapters run in. Code challenges, passkeys, the context resolvers and
the `mfa` context contributor come later (M3, M10) and are not described here.

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

- The whole capability is switched by `iam.adapters.mfa` (`IAM_ADAPTERS_MFA`), read in `register()` and leniently:
  `false` (as a boolean or as text), `0`, `off` and `no` turn it off, and anything else, a missing or empty value
  included, leaves it on. Off, nothing here is bound and each member keeps its own default. A test that changes it
  must do so before the providers register (`#[WithConfig(MfaSeams::SWITCH, false, defer: false)]`).
- A sign-in is one of `laravel-authentication`'s sessions, named as MFA names a sign-in (`Mfa\Translation\SignIn`):
  - MFA's application is the guard of the same name, which must be a declared guard of the `jwt` driver. Where MFA
    names no application (the freshness gate, the session revoker, the pending session resolver), it is the default
    guard, as `Auth::shouldUse()` leaves it, which is also what MFA names its application after when no application
    resolver is bound.
  - MFA's sign-in id is the session's key as a string (`SignIn::reference()`), which is always its primary key. A key
    that is neither a non-empty string nor an integer names nothing and is refused.
  - Where `laravel-authentication` names no session (at sign-in, before the session row is written, and whenever it
    asks for a requirement), every proof of the judgement is bound to `SignIn::UNNAMED` (`iam:unnamed-session`). It
    holds a colon, so no session key can equal it, and no adapter that reads a session's proofs produces it.
  - The identity is named as MFA names a proof's owner (`Mfa\Translation\IdentityReference`): its morph class for an
    Eloquent model and its class name otherwise, and its key, which must be an integer or a non-empty string. MFA's own
    rule is `@internal`, so it is restated here, and every comparison of two identities goes through it.
  - Every proof read from a session is stamped with the identity's current MFA verification generation
    (`VerificationGeneration::current()`, one read), since MFA trusts a proof only under the current generation.
- `Mfa\CurrentSession` resolves the guard and the sign-in for every adapter, so every adapter refuses the same
  misconfiguration the same way:
  - `defaultGuard()`, `guard()`, `caller()` (the identity the guard serves), `sessions()` (the guard's session
    service) and `identitySessions()` (the session service a change to the identity as a whole goes through: the
    default guard's when it is a `jwt` guard, otherwise the first `jwt` guard declared);
  - `current()` (the guard's current session, when it is the identity's), `of()` (that session, when it is also the
    sign-in MFA named) and `identity()` (MFA's identity as `laravel-authentication`'s);
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
    sign-in and purpose, with its `amr` without `mfa`, and with the evaluation of the proof on its own the adapter
    handing it over gives (`Mfa\ProofEvaluator`), never MFA's evaluation of the whole session the result carries.
- The evaluation a further proof is recorded with (`Mfa\ProofEvaluator`, IAM-3.2, IAM-3.5):
  `laravel-authentication` keeps it on the proof's own row, and its freshness reads "multifactor within so many seconds"
  as the newest proof flagged multifactor, timed by that proof. So the flag says whether this proof is the evidence of
  a multifactor combination with the session's first factor, never whether the session holds one: MFA's
  `VerificationResult::$evaluation` judges every proof of the session together, and would flag a fresh email code
  multifactor because of an authenticator app code proved hours before. MFA's requirement check judges the first
  factor and the proof alone, asking for multifactor authentication within a day
  (`FreshnessRequirement::MAX_AGE_SECONDS`) as if the proof had been made now and the first factor a second longer ago
  than that, so the part is met only on the proof's own evidence: a passkey sign-in that verified the person followed
  by an email code leaves the code unflagged. The first factor is the pending context's for a pending session and
  `ProofStoreAdapter::firstFactorOf()` for an active one; a session whose first factor is not known, and a proof the
  combination policy does not accept after it, are refused as `not_accepted`.
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
  - `PendingSessionResolverAdapter` (IAM-3.3) reads the pending credential where `laravel-authentication` reads it
    (the body field `authentication.session.pending_credential_field`: the JSON body, or the form body of a request
    other than `GET` and `HEAD`, never the query string) and answers `Auth::sessions()->pending()` on the default guard
    as MFA's pending context. No field is no pending session; a field that names no live pending session is refused.
  - `PendingCompletionAdapter` (IAM-3.3) calls `satisfy()` with the request's credential and the proof's own
    evaluation after the pending context's first factor as the last write of MFA's transaction, only inside a
    transaction on the storage connection, and returns the `SignInResult` as MFA's completion. `satisfy()` binds the
    guard only once that transaction commits, so a result never reaches a response when MFA's commit fails.
  - `StepUpAdapter` (IAM-3.4) checks the proof names the guard's identity and current session, reads the session's
    first factor (locking its row, after MFA's locks), and calls `stepUp()` with the proof's own evaluation after it;
    the `AccessTokenResult` is MFA's completion.
  - `ReauthenticatorAdapter` (IAM-3.5) checks the session is live through `firstFactor()` (locking its row inside a
    transaction) and answers the newest reauthentication `FreshnessPolicy::freshProof()` finds for
    `first_additional_factor` within MFA's five minutes; a session no longer live answers none.
  - `FreshnessGateAdapter` (IAM-3.5) asks `FreshnessPolicy::freshUntil()` about the default guard's current session for
    each part of the caller's requirement, each made stricter by the application's own setting in
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
  - `SessionRevokerAdapter` (IAM-3.7) calls `factorRemoved()` with the default guard's current session and returns
    `RemovalRevocation::judged()` carrying the `FactorRemoval` (its new pending credential included) as MFA's
    completion. A reset names no sign-in, so `revokeAll()` calls `factorReset()`, which ends the identity's sessions on
    every guard, through the default guard when it is a `jwt` guard and otherwise through the first `jwt` guard
    declared (`CurrentSession::identitySessions()`); it throws only when no `jwt` guard is declared.
  - `SessionTransitionAdapter` (IAM-3.8) calls `factorChanged()` on the sign-in MFA names and returns the
    `FactorChangeResult` as MFA's completion. The session is judged against the requirement `laravel-authentication`
    resolves, never MFA's `outstanding`.
  - `ProofStoreAdapter` and `FirstFactorResolverAdapter` (IAM-3.11) are `laravel-authentication`'s session proofs,
    read through `Auth::sessions()->proofs()` and `firstFactor()`. `currentSession()` is the guard's current session,
    `proofs()` its counting proofs oldest first, and the first-factor resolver its first factor. `begin()`, `forget()`
    and `forgetFactor()` write nothing. `record()` checks, in a transaction on the storage connection, that the proof is
    bound to the identity's current sign-in and that the session is live (`firstFactor() !== null`), and keeps only the
    sign-in's own first factor, which the session already holds; anything else throws MFA's `ProofRefusedException`.
    `laravel-authentication` is the only writer of a session's proofs. A proof that names a factor counts only while
    the identity still holds that factor in MFA's factor table, read on the write connection and only when a proof
    names one: MFA deletes a factor before it calls `forgetFactor()`, so the factor's proofs stop counting at once,
    inside MFA's own transaction, before the revoker's `factorRemoved()` voids them, and the proofs MFA reads back
    between the two already leave them out. Nothing is kept, so a removal that rolls back counts them again.
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
  name in `auth.guards`. The default guard is the one MFA names its application after.
- A sign-in: `Auth::sessions()->signIn()` asks the policy adapter, MFA composes the requirement, and the session starts
  active or pending. MFA's `verify()` on a pending session resolves it through the pending session resolver, and the
  completion calls `satisfy()` as MFA's last write; the session activates, and the guard is bound once MFA commits.
- A step-up with a stateless guard (the reproduction of sinemacula/laravel-iam#3): a bearer token's session verifies a
  further factor on one request, the step-up adapter records it on the session, and the next request with the same
  token meets the requirement, with no Laravel session started; another session of the same person does not.
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
- Two checks of MFA's `ProofStoreTests` kit cannot pass against `laravel-authentication`, which has no public write
  path for a first factor or a `sign_in` additional factor on an active session: both record a proof through the
  store and expect it kept as a new one. `ProofStoreAdapterTest` marks them skipped, with a message naming the gap (a
  follow-up to laravel-mfa #89, IAM-13.10: a kit hook for a store whose proofs only the authentication layer
  records), so the gap shows in every run, and checks what the store guarantees in their place under names of its
  own (`testASignInsProofsGoWhenLaravelAuthenticationSignsItOut`, `testAForgottenFactorStopsCountingAtOnce`). The
  other two run unchanged.
- A proof made with a factor the identity never held, or no longer holds, does not count, whatever
  `laravel-authentication` recorded: an application that hands `laravel-authentication` a step-up itself must name one
  of MFA's factors in it.
- MFA's test helper `InteractsWithMfa::actingAsVerified()` (`Testing\VerifiedSignIn`) does not work with this
  store: it records its further proof through `record()`, which refuses it, and the proof names a synthetic factor,
  which `proofs()` would leave out. An application's tests use `Testing\Concerns\InteractsWithIam`
  `actingOnVerifiedSession($session, $level)` instead, which acts on a signed-in session, enrols a confirmed fixture
  factor for its identity (an email factor for AAL1, an authenticator app for AAL2, a passkey for AAL3), steps the
  session up with a proof made with it through the step-up adapter, so `laravel-authentication` records it, and throws
  a `LogicException` unless MFA's route gate would read the session at exactly that level. The further proof is made
  now, so a freshness test verifies the session and then moves the clock on. The refusal `actingAsVerified()` meets
  names the helper. Closing the gap is a member change still needed in `laravel-mfa`: a hook in `VerifiedSignIn` for a
  store whose proofs only the authentication layer records, so its own helper can arrange them. The suite-wide
  `actingAsCaller()` (M9, IAM-12.2) builds on `actingOnVerifiedSession()`, not on `actingAsVerified()`.
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
  bound that verification fails where MFA's default would have recorded it.
- Every refusal `factorChange()` answers with, a session no longer live included, is MFA's `not_fresh`. A removal never
  counts a step-up made with the factor removed, even for the identity's only confirmed factor, and the first
  additional factor takes `laravel-authentication`'s reauthentication window (`first_additional_factor`, fifteen
  minutes by default) rather than MFA's five minutes.
- The freshness gate and a removal use the default guard, as MFA names no application for them: a removal made while
  the default guard is not a `jwt` guard throws and rolls back, and an application resolver bound later (M3) must name
  the same guard for a pending request and for the freshness gate. A reset is made wherever it is asked for (an admin
  panel's session guard, a console command, a queued job): it goes through the first `jwt` guard declared when the
  default guard is not one, and the guard it goes through forgets its binding to the identity once the reset
  commits.
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
- `src/Mfa/CurrentSession.php`: `of()`, `current()`, `identity()`, `caller()`, `defaultGuard()`, `guard()`,
  `sessions()`, `identitySessions()`, `isInTransaction()`.
- `src/Mfa/Translation/SignIn.php` (`UNNAMED`, `reference()`, `binding()`), `IdentityReference.php`,
  `ChannelTranslator.php`, `ProofTranslator.php` (`toMfa()`, `toResult()`), `RequirementTranslator.php` (`toMfa()`,
  `toAuthentication()`, `evaluation()`, `toFreshnessParts()`, `toFreshness()`, `fromFreshness()`),
  `ChangeTranslator.php`.
- `src/Mfa/AdditionalFactorPolicyAdapter.php`, `RequirementCheckAdapter.php`, `PendingSessionResolverAdapter.php`
  (`credential()`), `PendingCompletionAdapter.php`, `StepUpAdapter.php`, `ReauthenticatorAdapter.php`,
  `FreshnessGateAdapter.php` (`heldUntil()`), `FactorChangeGateAdapter.php` (`allowedUntil()`),
  `SessionRevokerAdapter.php`, `SessionTransitionAdapter.php`, `ProofStoreAdapter.php` (`firstFactor()`,
  `firstFactorOf()`, `held()`), `FirstFactorResolverAdapter.php`, `ProofEvaluator.php` (`evaluate()`).
- `src/Testing/Concerns/InteractsWithIam.php` (`actingOnVerifiedSession()`), `src/Testing/VerifiedSession.php`
  (`verify()`).
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
  `FirstFactorResolverTests`; two `ProofStoreTests` checks are skipped, see above), with their own cases on MySQL and
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
    `FactorChangeGateAdapterTest` (`testAChangeWithoutTheGuardsSessionIsRefusedAndRollsBack`),
    `SessionRevokerAdapterTest` (`testARemovalFromAnotherSignInIsRefusedAndRollsBack`), `SessionTransitionAdapterTest`
    (`testAChangeOnAnotherSignInIsRefusedAndRollsBack`), `ProofStoreAdapterTest`
    (`testARefusalRollsTheCallersTransactionBack`), `FirstFactorResolverAdapterTest`
    (`testAnUnresolvedSignInRollsTheCallersTransactionBack`).
- `tests/Integration/Mfa/FactorRemovalTest.php` `testTheOutstandingRequirementAgreesWithTheJudgedSession`,
  `testTheRemovedFactorStopsCountingInsideMfasTransaction`: a removal through MFA with every adapter bound reports a
  requirement outstanding exactly when `laravel-authentication` returned the session to pending
- `tests/Integration/Mfa/ProofStoreAdapterTest.php` `testAForgottenFactorStopsCountingAtOnce`,
  `testAFirstFactorMadeWithAFactorNoLongerHeldIsNone`, `testTheFactorsAreReadOnlyWhenAProofNamesOne`;
  `SessionRevokerAdapterTest.php` `testAResetMadeWhereTheDefaultGuardHoldsNoSessionsEndsEverySession`,
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
- `tests/Unit/Mfa/ProofEvaluatorTest.php` `testAFreshEmailCodeAfterAnOldAuthenticatorAppCodeIsNotMultifactor`,
  `testTheProofIsMultifactorOnlyOnItsOwnEvidence`; `tests/Integration/Mfa/MultifactorEvidenceTest.php`
  `testAFreshWeakerProofNeverRefreshesAnOldMultifactorOne` (a fresh email code after an old authenticator app code is
  not fresh multifactor authentication, before or after the authenticator app is removed, as MFA's own check judges);
  `PendingCompletionAdapterTest` `testEachProofIsRecordedWithItsOwnEvaluation`
- `tests/Integration/Mfa/StatelessVerificationTest.php` `testAVerificationCountsOnTheNextRequestWithTheSameToken`
- `tests/Performance/Mfa/RequirementQueryBudgetTest.php`; `benchmarks/Mfa/RequirementCheckBench.php`
- `tests/Feature/Testing/InteractsWithIamTest.php` `testMfasActingAsVerifiedIsRefusedByThisPackagesStore`,
  `testAVerifiedSessionPassesMfasRouteGate`, `testTheFurtherProofIsRecordedWithAFactorThePersonHolds`

## Change Triggers

Update this note when:

- a member renames, adds or removes one of the seams in the table, or changes a default's class or binding style;
- `laravel-authentication` gains a public write path for a session's proofs, or a single-factor void (the proof store
  could then record and forget, and its kit could run unchanged), or `laravel-mfa`'s `ProofStoreTests` gains a hook
  for a store whose proofs only the authentication layer records (the two skipped checks then run);
- MFA stops deleting a factor before it calls `forgetFactor()`, or changes what a proof's reference names;
- `laravel-mfa`'s `VerifiedSignIn` gains a hook for a store whose proofs only the authentication layer records, or
  changes the evidence it records for a level (`actingOnVerifiedSession()` records the same evidence);
- MFA gains an application parameter on the freshness gate or the session revoker, or an application resolver adapter
  lands (M3);
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
- MFA's `VerificationResult` gains an evaluation of the new proof on its own, which `ProofEvaluator` would then take.
