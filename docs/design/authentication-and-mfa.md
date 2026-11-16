# Authentication and MFA

## Purpose

How the package joins `laravel-authentication` and `laravel-mfa`: the seams `Mfa\MfaSeams` binds, how an MFA sign-in
maps to an authentication session, how the members' types are translated, the `mfa` context namespace, and the lock
order. Code challenges, passkeys, the context resolvers and code delivery are in `codes-delivery-and-passkeys.md`.

## Seams

`iam.adapters.mfa` switches the whole capability; only a false-like value turns it off. Every adapter is transient and
replaces only its member's default (`binding-precedence.md`). Only the session revoker is mandatory: on MFA's default, a
removed factor would leave the identity's other sessions standing.

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

## Decisions

- An MFA application is the `jwt` guard of the same name, and a sign-in is one of that guard's sessions, named by its
  key as a string (`Translation\SignIn`). `Mfa\CurrentSession` resolves both for every adapter, so every adapter
  refuses a misconfiguration the same way.
- Adapters act on the values MFA hands them (`CallerContext`, the application, the sign-in), never the request the
  container holds. Where MFA names the sign-in (a factor change, a transition, a removal), the adapter reads it by key
  whatever the guard holds, so a change from a job or console acts on the right session. Only
  `PendingSessionResolverAdapter::fromRequest()` reads a request directly; the guard reads its own bearer token.
- MFA names an active caller's sign-in only through `ProofStore::currentSession()`, so the proof store's
  `currentSession()`, `proofs()` and `firstFactor()`, the freshness gate and the reauthenticator answer from the guard's
  current session, and only while it serves the identity MFA passed (`CurrentSession::held()`). `proofs()` answers
  nothing for another sign-in, and `record()` accepts a proof only for the guard's current sign-in. Off a request,
  unless a command or job signs in on the guard itself, there is no current sign-in: the proof store answers none, the
  freshness gate finds nothing fresh and the reauthenticator throws `UnresolvedReferenceException`.
- `laravel-authentication` is the only writer of a session's proofs. The proof store reads them and accepts only the
  sign-in's own first factor; further proofs arrive through `stepUp()` and `satisfy()`. So rebinding `StepUp` or
  `PendingCompletion` back to MFA's `ProofStoreCompletion` refuses every verification: rebind both or neither.
  `begin()`, `forget()` and `forgetFactor()` write nothing, since authentication starts, ends and voids sessions.
- A recorded proof is accepted, and multifactor only when `VerificationResult::$refreshesMultifactor` says the proof
  itself refreshes that evidence. Authentication's configured freshness times multifactor by the newest flagged proof,
  and MFA's whole-session evaluation would flag a fresh email code because of an authenticator app code proved hours
  before.
- Where authentication names no session (at sign-in, and when it asks for a requirement), every proof is bound to
  `SignIn::UNNAMED`, which no session key can equal. Each proof is stamped with the identity's current verification
  generation.
- The additional-factor policy asks MFA's `RequirementPolicy`, which answers for the identity and the application and
  leaves every tenant's requirement to the tenant policy (`tenant-authentication-policy.md`). It hands MFA the first
  factor with `ProviderTrust::withheld()`, since no tenant's trust counts toward the identity's own requirement.
- The requirement check hands MFA an external provider's first factor naming no connection
  (`ProviderTrust::withheld()`): authentication has already asked its external evidence policy for the tenant. MFA's own
  session judgements name the connection only for evidence SSO accepted, from a connection the tenant trusts.
- The pending completion is the last write of MFA's transaction, and `satisfy()` binds the guard only on commit, so a
  sign-in result never reaches a response when MFA's commit fails.
- The factor-change gate replaces MFA's freshness check with `laravel-authentication`'s `factorChange()`, which judges
  the session's proofs as committed under its row lock; the adapter takes the verdict as it is.
- The freshness gate and the reauthenticator ask current inside a transaction on the storage connection, as
  authentication's `StorageConnection::isInTransaction()` reports it, locking the session row and reading committed
  proofs, and plainly outside one, where nothing acts on the answer atomically.
- The freshness gate hands the caller's requirement whole to authentication's `metUntil()`, which judges it, a minimum
  level included, by the requirement check or accepted provider evidence, apart from the operation's configured
  freshness, and answers the earlier deadline. A part with no maximum age, or one over a day, throws
  `InvalidArgumentException`.
- The factor-change gate hands `factorChange()` the requirement whole, judged as `metUntil()` judges it without the
  removed factor's proofs; a part with no maximum age, or one over a day, is held to a day.
- A reset names no guard, so it goes through `Auth::sessions()`, which picks the `jwt` guard.
- `MfaContextContributor` fills the `mfa` namespace with MFA's own `contributeFor()`, from the contribution subject's
  session and its newest proofs, so the keys match `Mfa::authenticationContext()` for that session. It is registered
  only while the switch is on and nothing else holds `mfa`.
- `laravel-authentication` writes a session's proofs only alongside its own token issuance, under the session's row
  lock, so the proof store records and forgets nothing.

## Invariants

- Values both members spell the same cross by value; anything one member would refuse is refused with its own
  exception, never shortened. Two things are left out: a provider proof's connection, unless SSO accepted its evidence
  from a connection the tenant trusts, and, in `SignInProofs`, a session's proof MFA cannot express.
  `external_reauthentication` is MFA's first-factor reauthentication on the `external_provider` channel, and MFA's
  `unclassified` level is no level.
- Refusals are thrown inside the transaction the member opened, so whatever it changed rolls back: MFA's
  `OperationRefusedException` (`not_accepted` for the step-up and pending completion, `not_fresh` for the factor-change
  gate, with authentication's reason in the detail), `ProofRefusedException` from `record()`, and
  `UnresolvedReferenceException` or `SessionMismatchException` for a guard, session or identity that cannot be resolved.
- Lock order: MFA's identity state, then its factors, then `laravel-authentication`'s session row, then its proofs. A
  removal then takes the identity's other sessions' rows in `factorRemoved()`. Adapters that only read (the policy, the
  requirement check, the pending session resolver) take no lock of their own; asked current through the freshness gate,
  the requirement check reads the session's proofs under authentication's shared locks and MFA's verification generation
  plainly.
- MFA opens its own transaction for a verification, a factor change, a removal and a reset, and never retries it, so
  these flows must not run inside `Iam::transaction()` or any transaction the application opens. A concurrency failure
  reaches the caller, who retries the request.
- On MySQL and MariaDB at REPEATABLE READ, a removal holding the gaps around the current session's proofs and a step-up
  of a neighbouring session can deadlock; the database fails one side and the caller retries. Authentication keeps this
  order by design.
- In tests, `VerifiedSignInRecorderAdapter` lets MFA's `actingAsVerified()` sign in through authentication; the
  helpers built on it are described in `docs/guides/testing.md`.
