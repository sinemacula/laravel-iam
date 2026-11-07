# SSO Redemption and Revocation

## Purpose

This note describes how the package joins `laravel-authentication` and `laravel-sso` for redeeming SSO's handoff
codes (IAM-4.1 sign-in, IAM-4.2 re-authentication, IAM-4.3 links), for ending sessions when SSO changes what they rest
on (IAM-4.4) and for SSO's own link store (IAM-4.9). It covers the seams `Sso\SsoSeams` binds, the three redemption
services the application calls, the records they keep for one request, the transaction and the lock order each runs
in, which refusals commit and which roll back, how SSO's identity and tenant references are resolved, and the gaps in
the members the adapters work around. The enforcement policy, freshness, link e-mail matching, the `sso` context
contributor (M5), the tenant tree and scope widening's trigger (M6) and provisioning (M7) come later and are not
described here; the binding rule that applies every row is in `binding-precedence.md`, and the storage connection and
retry helper the redemptions run through are in `storage-and-transactions.md`.

## Invariants

- `Sso\SsoSeams` declares every binding, and the binding rule applies them in `register()`. Each row replaces only its
  member's own default, and a binding the application made before or after the members register is kept (IAM-8.4).

  | Member seam                         | Bound to                          | Member default replaced      | Lifetime  |
  | ----------------------------------- | --------------------------------- | ---------------------------- | --------- |
  | SSO `ReauthenticationSessions`      | `ReauthenticationSessionsAdapter` | `NoReauthenticationSessions` | transient |
  | SSO `SessionRevocation` (mandatory) | `SessionRevocationAdapter`        | `NoSessionRevocation`        | transient |
  | AUTH `ExternalIdentityLinks`        | `ExternalIdentityLinksAdapter`    | `NoExternalLinks`            | transient |
  | SSO `Linker`                        | SSO's `Links\LinkStore`           | `NoLinks`                    | scoped    |
  | SSO `LinkStorage`                   | `BoundLinkStorage`                | none (while unbound)         | scoped    |

- Session revocation is the one mandatory row (IAM-4.4): left on SSO's default, an enforcement change, a disabled or
  deleted connection, a removed link or a widened scope would leave every session it concerns standing.
- The whole capability is switched by `iam.adapters.sso` (`IAM_ADAPTERS_SSO`), read in `register()` and leniently, as
  `iam.adapters.mfa` is: `false` (as a boolean or as text), `0`, `off` and `no` turn it off, and anything else, a
  missing or empty value included, leaves it on. Off, nothing here is bound and each member keeps its own default.
- SSO's `HandoffIssuer` is never declared: SSO issues and redeems its own handoff codes, so it stays on
  `Handoffs\DatabaseHandoffStore` in every provider order and with the switch off, and no `HandoffRecheck` is used.
- Links are SSO's: `laravel-authentication` stores none. SSO finds its link storage only as the bound `Linker` that
  implements `LinkStorage`, so `Linker` is bound to SSO's own `Links\LinkStore`, and `LinkStorage`, which SSO never
  binds, only while it is unbound, to `BoundLinkStorage`, which answers every call from whatever `Linker` is bound at
  that moment: the store by default, and an application's own linker once it binds one. Whatever resolves
  `LinkStorage` then reads and writes exactly the links SSO resolves, never past a linker the application put in front
  of the store or bound to link nothing; a bound linker that is no link storage (SSO's `NoLinks` among them) is a
  `LogicException` before anything is read or written. Neither keeps anything of one request for the next, but each
  holds the container (the store and its event dispatcher resolve from it), so both are scoped under this package's
  scoped prefix (as SSO's own guide binds the store), forgotten by `Iam::resetWorkerState()`, and a long-lived worker
  never reaches one request's container from another (IAM-8.1), as it would through a shared instance.
- One core method for each action, taking plain values:
  - `SignInRedemption::redeem(string $application, string $connectionId, string $code, string $verifier,
    SignInContext $context): RedemptionResult|SignInResult`. It takes `laravel-authentication`'s `SignInContext`, not
    a bare `ClientContext`, because `signInExternally()` requires one: the caller's principal, tenant selection, client
    name and deadline reach the sign-in unchanged, and SSO's client is built from `$context->client`.
  - `ReauthenticationRedemption::redeem(string $application, string $connectionId, string $code, string $verifier,
    ClientContext $client): AccessTokenResult|RedemptionResult`.
  - `LinkRedemption::redeem(string $application, string $connectionId, string $code, string $verifier,
    ClientContext $client, Identity $caller): RedemptionResult`. The caller is handed over as
    `laravel-authentication`'s `Identity`, the identity of the session the request is served with, which the
    application reads where it reads the request; it is never read from `Auth::identity()` nor from the request's
    body.
  - The code and the verifier are `#[\SensitiveParameter]`. The `ClientContext` is `laravel-authentication`'s, built
    with `ClientContext::fromRequest()` or `SignInContext::fromRequest()` where the request is read, or as
    `new ClientContext(null, null)` from a job or a command, whose events then carry no IP address or user agent. SSO's
    own `ClientContext` is built from it in one place (`Sso\Translation\ClientTranslator::toSso()`), with the IP address
    and user agent, the two values SSO's carries.
  - The application reaches each service through an accessor of the manager and the facade (`Iam::signIns()`,
    `Iam::reauthentications()`, `Iam::links()`), never through a second method that repeats one's signature. No
    service, adapter or record reads a request, a cookie, a header, the guard's current user or its current session.
- The application SSO names is the guard of the same name, which must be a declared guard of the `jwt` driver
  (`CurrentSession::sessions()`, `CurrentSession::guard()`); anything else throws `UnresolvedReferenceException(guard)`.
  Every redemption resolves it before SSO is asked, so the code is never touched for an application that is no guard:
  a sign-in and a re-authentication inside their transaction, and a `link`, which writes no session and so only
  resolves the guard, before SSO's standalone `redeem()` opens its own transaction or, inside the caller's, before its
  savepoint. A guard the code was not started for is SSO's `application_mismatch`, answered once SSO has consumed the
  code.
- Transactions (IAM-11.1, IAM-11.2):
  - A sign-in and a re-authentication run in one transaction on the storage connection, the one Laravel connection
    `sso.storage.connection` and `authentication.storage.connection` both resolve to (the boot check refuses a
    mismatch), opened through `CrossMemberTransaction::run()`. SSO's `admit()` and `laravel-authentication`'s
    external sign-in or re-authentication each run as a savepoint of it, and their events wait for its commit.
  - A serialisation failure, a deadlock or SSO's `LinkCandidatesChanged` runs the whole redemption again, and only
    when the package opened the outermost transaction; inside a caller's it is thrown on to the caller's retry.
  - A `link` is redeemed through SSO's standalone `redeem()` with no transaction of this package's: SSO opens its own,
    retries itself once on `LinkCandidatesChanged`, and commits before it answers. It is redeemed but never admitted.
    Called inside a transaction the caller holds open on the storage connection, SSO's `redeem()` is its `admit()`
    instead: the link is admitted, written in the caller's transaction, and commits or rolls back with it. Which path
    runs is SSO's; this package refuses neither.
  - A standalone `link` whose transaction a concurrency failure ends before it commits (SQLSTATE 40001, a deadlock, a
    lock wait timeout, or a second `LinkCandidatesChanged`) has been rolled back whole by SSO, its consumption
    included, so `LinkRedemption` redeems it again from its start, still standalone, up to `iam.transactions.attempts`
    (`RetrySettings`), after the failures `ConcurrencyFailures::isRetryable()` recognises. It is never wrapped in
    `CrossMemberTransaction::run()`, which would make it an admitted redemption. On PostgreSQL at REPEATABLE READ, a
    `link` that waited on another holder of the identity's guard (a second submission of the same callback, another
    link of the same person's, a reservation's activation or a principal's widening) fails to serialise once the other
    commits, and the next attempt sees what it committed. Each attempt is counted against the client's IP address, as
    SSO counts every redemption.
  - A standalone `link` attempt that reached its commit is never run again, whatever it then failed on, as
    `CrossMemberTransaction` never runs an attempt again once it has committed: SSO dispatches `HandoffRedeemed`,
    `LinkCreated` and its other events from the commit, and a listener's exception (a deadlock met writing an audit
    row, say) propagates from it, after the link is written and the code spent, so a second attempt would only find
    the code replayed, answer a refusal of a link that was made, report a spurious `FlowFailed(replayed)` and spend
    another attempt. Laravel fires `TransactionCommitting` just before it commits an outermost transaction, and this
    package counts each one for the request (`Transactions\OutermostCommits`, listened for in
    `IamServiceProvider::registerCommitCounting()`); an attempt during which the storage connection's count moved
    rethrows its failure as it was thrown. A commit that itself failed is counted too, which errs on the side of not
    retrying: the caller retries the request.
  - Inside a caller's transaction a `link` runs once, through `CrossMemberTransaction::run()`, in a savepoint of the
    caller's transaction that is rolled back whenever it fails, after a concurrency failure included, on every
    supported Laravel version (Laravel before 13.40 only lowers the level), so a caller that catches the failure and
    commits keeps none of SSO's writes: not the consumption, the single-use record or the link. SSO still sees a
    transaction open and admits the link. Its failure reaches the caller through `ConcurrencyFailures::forCaller()`,
    in a form the caller's retry recognises.
  - The code and the verifier reach the transaction's work in a sign-in, a re-authentication and a `link` inside a
    caller's transaction wrapped in a `SensitiveParameterValue` and are unwrapped only inside it, so a trace of
    anything thrown there, whose frames carry the work and what it captured, holds neither in the clear; a standalone
    `link` captures neither in any closure.
  - SSO's flow starts and completions are never wrapped in a transaction.
- Records for one request (IAM-8.1): `AdmittedRedemptions` holds at most one admitted redemption, with the identity and
  the link SSO resolved, `RenewalRecorder` at most one renewal, and `Transactions\OutermostCommits` the outermost
  commits each connection has begun. All three are bound scoped under `BindingRule::SCOPED_PREFIX` and resolved
  through that key (`IamServiceProvider::registerRedemptionRecords()`), so the worker reset forgets them, and every
  adapter, listener and redemption resolves them from the container on each call. Each redemption forgets the
  admitted redemption and the renewal as each attempt starts and again as it ends, so a retried attempt never meets a
  record of one rolled back, and nothing later in the request answers from a redemption that is over.
- A `reauthenticate` code is redeemed through `Iam::reauthentications()` alone. The renewal recorder is open only while
  one of its attempts runs (`RenewalRecorder::open()`, `close()`, which count the openings, so a redemption run while
  another is open in the same container leaves the other open), and a renewal SSO asks for while it is closed, as
  when the application admits a `reauthenticate` code through SSO's own `HandoffRedemption::admit()`, is one no
  redemption would write: it is a `LogicException`, which rolls that admission back and leaves the code unspent, with
  nothing reported, rather than let SSO commit it as redeemed and report a renewal the session's freshness never
  saw.
- `laravel-authentication`'s link contract answers only from the redemption admitted in this request
  (`ExternalIdentityLinksAdapter`): `ExternalLink(identity, linkId)` when the connection, issuer and subject are
  exactly the admitted result's, and `null` otherwise, or when the admission names no link. It never looks a link up
  again, since `find()` cannot carry the NameID format.
- The external result is built from the redemption alone, never from anything the client sends
  (`Sso\ExternalResults`):
  - `from()`, for a sign-in: the connection, issuer and subject, tenant and request reference from SSO's verified
    result; `authenticatedAt` from its authentication context (which may be `null`); the session deadline, the
    enforcement version as the policy version and the link from the redemption; the evidence as
    `ExternalEvidence(methods, rawContext, authenticatedAt)` of SSO's accepted evidence; and the provider context as
    exactly `Provenance::toArray()` of the provenance SSO captured.
  - `renewing()`, for a re-authentication: the same, with `authenticatedAt` and the evidence of the renewal SSO
    recorded, and no provider context.
- The re-authentication sessions adapter (`ReauthenticationSessionsAdapter`):
  - `standing()`, as a flow starts and outside any transaction, asks `externalStanding()` with no link on every
    declared `jwt` guard (`CurrentSession::sessionGuards()`), and answers `signed_in` when any answers `null`. SSO
    names no application there, and a session stands only on its own guard (any other answers
    `session_guard_mismatch`), so asking the default guard alone would refuse every other guard's sessions.
  - `lockedStanding()`, inside the redemption's transaction and after SSO's locks, asks `externalStanding()` through
    exactly the link on the application's guard, which locks the session's row until the transaction ends.
    `laravel-authentication` compares the session's guard with the application's itself, so no comparison of the
    adapter's own is made. Asked outside a transaction on the session model's connection it could lock nothing, so it
    throws a `LogicException` rather than answer unprotected.
  - Every reason `laravel-authentication` gives (`session_unknown` and `session_guard_mismatch` among them) is
    `not_signed_in`: an answer, never a throw. Only an unresolvable identity reference or application throws.
  - `renewAuthentication()` writes nothing: it records the renewal, and a second in one redemption, or one asked for
    while no redemption is open to write it, is a `LogicException`.
- Revocation (`SessionRevocationAdapter`) maps each of SSO's four scopes to the one `laravel-authentication` helper
  that ends exactly those sessions, through the session service for a change to the identity as a whole
  (`CurrentSession::identitySessions()`), since every helper covers every guard:

  | Scope kind (reason)                    | Helper                                      | Switch                     |
  | -------------------------------------- | ------------------------------------------- | -------------------------- |
  | `tenant` (`enforcement_changed`)       | `tenantPolicyChanged($tenant)`              | none (mandatory)           |
  | `connection` (`connection_disabled`)   | `connectionDisabled()`                      | `laravel-authentication`'s |
  | `connection` (`connection_deleted`)    | `connectionDeleted()`                       | `laravel-authentication`'s |
  | `identity_connection` (`link_removed`) | `linkRemoved()`                             | `laravel-authentication`'s |
  | `identity_link` (`scope_widened`)      | `linkScopeWidened()`, never `linkRemoved()` | none (idempotent)          |

  Each helper runs as a savepoint of SSO's transaction on the shared connection, throws on failure, and reports a
  revocation only once SSO's change commits, so nothing is reported that was not done. A connection scope with any
  other reason, and a scope missing what its kind names, throws a `LogicException`.
- References (IAM-8.2):
  - `IdentityReferences::identity()` maps SSO's `IdentityReference` through the morph map
    (`Relation::getMorphedModel($type) ?? $type`) to an Eloquent model implementing `laravel-authentication`'s
    `Identity`, skips the query for an id that cannot be the model's key, finds it on the write connection with the
    model's own query (its global scopes kept, so a hidden or deleted identity is never signed in), and requires the
    one found to be named by exactly that reference: its morph class is the type and its key, as a string, is the id
    byte for byte, so a collation that matches another case, trailing spaces or an upper-case UUID never resolves a
    reference SSO keys as another identity to this one. Anything else throws `UnresolvedReferenceException(identity)`,
    with the id kept out of the message. `reference()` names an Eloquent identity by its morph class and its key as a
    string, and throws for an identity that is no model or whose key is neither a non-empty string nor an integer.
  - `Tenancy\TenantReferences::tenant()` asks `laravel-authentication`'s `TenantResolver`, resolved on each call,
    inside `WriteConnection::during()` as `laravel-authentication` asks it, so the resolver's model reads are pinned to
    the write connection on whichever connection the tenant lives, and accepts only a tenant whose identifier, as a
    string, is the id SSO named; anything else throws `UnresolvedReferenceException(tenant)`.
- Lock order. Every adapter follows SSO's, each lock taken only when its condition holds: the identity guard, the
  enforcing tenant's rule, the connection with the rule's connections in ascending order, the reservation's domain
  claim, the handoff code, the links, the application's guards, `laravel-authentication`'s connection guard rows, and
  the session's row, always last. No adapter takes a lock after `reauthenticateExternally()`, and nothing locks a
  session's row and then calls into SSO. The "authorisation request" lock the requirements list between the domain
  claim and the handoff code is not taken by a redemption in the installed SSO, so it does not appear.

## Success Path

1. Sign-in: the application calls `Iam::signIns()->redeem(...)` with a `SignInContext` it built from the request. In
   one transaction on the storage connection the guard is resolved, SSO admits the code (its locks in its order), the
   admitted redemption is recorded, and `signInExternally()` signs the linked identity in once, on the guard, through
   the link contract's answer of exactly that link, writing the session and its provenance after
   `laravel-authentication`'s connection guard, so the session's row is the last lock. An active or a pending result
   commits, one `HandoffRedeemed` follows the commit, and the credential leaves only then, sent with
   `Cache-Control: no-store`.
2. Re-authentication: `Iam::reauthentications()->redeem(...)` admits the code in one transaction; SSO asks the locked
   standing of the session the code names (its row locked last) and its renewal, which is recorded. Once SSO answers
   redeemed and admitted, the renewal is taken, must be for the session the redemption names, and
   `reauthenticateExternally()` makes the one write: `auth_time` becomes the later of the session's and the
   provider's, and refresh tokens, deadlines, provenance and earlier evidence stay unless this authentication's own
   evidence was accepted. No renewal is still recorded when it commits, and the token leaves after the commit.
3. Link: `Iam::links()->redeem(...)` resolves the application to its guard, names the caller to SSO and calls SSO's
   standalone `redeem()`, which commits the link before it answers (inside a transaction the caller holds open, it
   writes the link in a savepoint of that transaction instead); no session is written.
4. Revocation: an SSO change (a connection disabled or deleted, a link removed, a scope widened, an enforcement change)
   calls `revoke()` inside its own transaction; the adapter resolves the identity or tenant and ends exactly the
   sessions the scope names, which commit, or roll back, with SSO's change.

## Failure / Edge Cases

- SSO's refusal (an unknown code, a mismatching verifier, a replay, `session_ineligible`, `identity_mismatch` and the
  rest) is answered as the `RedemptionResult`, and commits: a code SSO consumed stays spent, and one `FlowFailed`
  follows the commit. A rate-limited redemption is answered the same way.
- `laravel-authentication`'s refusal rolls back: a failed `SignInResult` throws `ExternalSignInRefusedException` and a
  failed `AccessTokenResult` throws `ExternalReauthenticationRefusedException`, each carrying the result, so the code
  stays unspent, no reservation is activated and no `HandoffRedeemed` or `ReauthenticationCompleted` is reported. A
  result naming another link than the session's is `link_mismatch`, and rolls back the same way, and so does a session
  write that throws, which reaches the caller as it was thrown, undoing the connection's first completed sign-in SSO
  acknowledged in the transaction with the consumption. SSO counts the attempt on the storage connection unless
  `sso.rate_limits.connection` names another, so that attempt's count rolls back too; only a code admitted with its
  verifier reaches `laravel-authentication`, so no guess is forgiven.
- An admitted `sign_in` linked to no identity (issued only to an application allowing unlinked handoffs) throws
  `UnlinkedSignInException` before `laravel-authentication` is asked, and rolls back.
- A re-authentication that SSO admits with no renewal recorded, with a renewal for another session, or with one still
  recorded when SSO refused, throws a `LogicException` inside the transaction, and rolls back; the external
  re-authentication is never called when SSO refused, and never from `renewAuthentication()`. A `reauthenticate` code
  admitted through SSO's own `admit()`, outside `Iam::reauthentications()`, throws the recorder's `LogicException`
  from SSO's admission, and the caller's transaction rolls back with the code unspent.
- A standalone `link` whose commit, or anything run from it, fails is not redeemed again: the failure reaches the caller
  as it was thrown, with the link written and the code spent when the commit itself succeeded, and no second
  `FlowFailed` is reported.
- An application that is no `jwt` guard throws `UnresolvedReferenceException(guard)` before the code is touched, a
  `link`'s as a sign-in's and a re-authentication's; a caller that cannot be named throws
  `UnresolvedReferenceException(identity)` before the link code is touched.
- An identity reference SSO hands a revocation or a standing that names nobody throws, and rolls SSO's change or the
  redemption back: a link whose identity was deleted is kept rather than removed with its sessions standing.
- With `laravel-authentication`'s default `ResolveNoTenant`, every enforcement change throws until the application
  binds a tenant resolver. Until a `TenantAuthenticationPolicy` is bound (M5), `tenantPolicyChanged()` revokes nothing.
  SSO names only the enforcing tenant and cannot list the tenants that inherit its rule, so only the enforcing tenant
  is judged until the application's tenant tree arrives (M6): SSO's `EnforcementInheritance` maps a tenant up to its
  enforcing tenant only, and cannot list the tenants below it.
- Until freshness (M5) and link eligibility (M6) are bound, SSO's defaults refuse every link (`freshness_required`,
  `link_ineligible`); the integration tests stand in SSO's `Testing\FakeFreshness` and a fixture that lets everyone
  link.
- On PostgreSQL at REPEATABLE READ, a sign-in racing a connection disable or a link removal, and two re-authentications
  racing for one session, make the later of each pair fail to serialise; the retry helper runs it again from its start
  and it sees what the other committed. A `link` racing another holder of the identity's guard fails to serialise the
  same way, and `LinkRedemption` redeems it again, standalone. On every other engine and level the later waits on the
  earlier's locks.
- A concurrency failure the attempts do not outlast (the last attempt's), and any other failure, reaches the caller as
  the database raised it: from a redemption this package opened the transaction for, or a standalone `link`, the
  database's `QueryException` (SQLSTATE 40001, or MySQL's 1213 or 1205), never the `DeadlockException` Laravel wraps
  it in where a member's nested transaction met it, which loses both and which Laravel's detector cannot recognise
  around PostgreSQL's serialisation failure (`ConcurrencyFailures::asRaised()`); inside a caller's transaction, the
  failure as that caller's retry recognises it. The code stays unspent and nothing is reported, so the caller retries
  the request, as it does for MFA's own transactions (`authentication-and-mfa.md`).
- Gaps in the members that the adapters work around:
  - `laravel-sso`'s `ReauthenticationSessions::standing()` names no application although `StartEligibility` knows it,
    so every `jwt` guard is asked (one read per guard, at flow start only).
  - `laravel-sso`'s `RevocationScope::tenant()` names only the enforcing tenant, and nothing lists the tenants that
    inherit its rule.
  - `laravel-authentication` has no public helper to resolve an identity from a morph type and key or to check a key's
    shape; `IdentityReferences` reuses `SessionKeyShape::matches()`, which works on any model.
  - Neither member ships a contract kit for `ReauthenticationSessions`, `SessionRevocation`, `Linker`/`LinkStorage` or
    `ExternalIdentityLinks`, so IAM-8.3 has none to extend here.
  - `laravel-sso`'s guide for this package shows `signInExternally()` without its `SignInContext`,
    `reauthenticateExternally()` without its `ClientContext`, and `Auth::sessions()` with no guard, the default guard
    only; the adapters pass both contexts and use the application's guard.

## Implementation Anchors

- `src/Sso/SsoSeams.php`: `seams()`, `isOn()`, `SWITCH`; `src/Sso/BoundLinkStorage.php`; `config/iam.php`:
  `adapters.sso`;
  `src/IamServiceProvider.php`: `registerRedemptionRecords()`, `registerCommitCounting()`, `seamProviders()`;
  `src/Transactions/OutermostCommits.php`: `committing()`, `count()`;
  `src/Transactions/ConcurrencyFailures.php`: `asRaised()`, what a redemption's last failure reaches the caller as.
- `src/Sso/SignInRedemption.php`, `src/Sso/ReauthenticationRedemption.php`, `src/Sso/LinkRedemption.php`: `redeem()`;
  `src/IamManager.php`: `signIns()`, `reauthentications()`, `links()`; `src/Facades/Iam.php`.
- `src/Sso/AdmittedRedemptions.php`: `record()`, `matching()`, `forget()`; `src/Sso/RenewalRecorder.php`:
  `open()`, `close()`, `record()`, `take()`, `isHolding()`; `src/Sso/Renewal.php`.
- `src/Sso/ExternalResults.php`: `from()`, `renewing()`; `src/Sso/Translation/ClientTranslator.php`: `toSso()`.
- `src/Sso/ReauthenticationSessionsAdapter.php`: `standing()`, `lockedStanding()`, `renewAuthentication()`;
  `src/Mfa/CurrentSession.php`: `sessions()`, `sessionGuards()`, `identitySessions()`, `isInTransaction()`.
- `src/Sso/ExternalIdentityLinksAdapter.php`: `find()`; `src/Sso/SessionRevocationAdapter.php`: `revoke()`.
- `src/Sso/IdentityReferences.php`: `identity()`, `reference()`; `src/Tenancy/TenantReferences.php`: `tenant()`.
- `src/Exceptions/UnlinkedSignInException.php`, `src/Exceptions/ExternalSignInRefusedException.php`,
  `src/Exceptions/ExternalReauthenticationRefusedException.php`; `src/Exceptions/UnresolvedReferenceException.php`:
  `forGuard()`, `forIdentityReference()`, `forTenant()`.

## Authoritative Tests

- `tests/Feature/Sso/SsoSeamsTest.php` `testEveryAdapterIsBoundOverItsMembersDefaultInEveryProviderOrder`,
  `testTheHandoffIssuerKeepsSsosOwnStoreInEveryProviderOrder`,
  `testAnApplicationBindingMadeBeforeAnyProviderRegistersIsKept`,
  `testAnApplicationBindingMadeOnceEveryProviderHasRegisteredWins`,
  `testTheLinkStoreIsScopedAndForgottenWhenTheWorkerResets`, `testTheLinkStorageIsTheBoundLinkersOwn`,
  `testTheSwitchOffBindsNothing`,
  `testTheSwitchIsReadLeniently`, `testEachBindingsLifetimeDefaultsAndMandate`
- `tests/Feature/Sso/RedemptionRecordsTest.php` `testTheRecordIsOneInstanceForTheUnitOfWork`,
  `testTheWorkerResetForgetsTheRecord`; `tests/Feature/IamServiceProviderTest.php` `testEachOutermostCommitIsCounted`,
  `testOutermostCommitsAreCountedWithTheWorkerResetOff`; `tests/Unit/Transactions/OutermostCommitsTest.php`
  `testEachCommitIsCountedForItsOwnConnection`
- `tests/Feature/IamManagerTest.php` `testEachRedemptionIsReachedThroughItsOwnService`;
  `tests/Feature/Facades/IamTest.php` `testTheRedemptionsAreReachedThroughTheFacade`,
  `testTheFacadeAnnotatesExactlyTheManagersSurface`
- `tests/Integration/Sso/SignInRedemptionTest.php` `testALinkedSignInSignsThePersonIn`,
  `testARefusalBySsoCommitsAndSpendsTheCode`, `testARefusalByAuthenticationRollsBackAndLeavesTheCodeUnspent`,
  `testAnUnlinkedSignInIsRolledBack`, `testAPendingSignInCommits`,
  `testAnApplicationThatIsNoSessionGuardThrowsBeforeTheCodeIsTouched`,
  `testARedemptionInsideTheCallersTransactionCommitsWithIt`, `testTheAdmittedRedemptionIsTheRedemptionsAlone`,
  `testASessionWriteThatThrowsLeavesTheCodeUnspentAndNoSignInAcknowledged`,
  `testTheProvenanceNamesTheEnforcementVersionJudgedAtRedemption`, `testTheProvidersSessionDeadlineCapsTheSession`,
  `testARawContextClassOutsideTheStoredDomainSignsInWithItNone`
- `tests/Integration/Sso/ReauthenticationRedemptionTest.php` `testTheRenewalIsWrittenOnceForTheRecordedSession`,
  `testAnOlderProviderTimeLeavesTheSessionsOwn`, `testARefusalBySsoCommitsAndSpendsTheCode`,
  `testAFailedTokenResultRollsBackAndLeavesTheCodeUnspent`, `testABrokenRenewalIsALogicExceptionThatRollsBack`,
  `testAnApplicationThatIsNoSessionGuardThrowsBeforeTheCodeIsTouched`, `testTheRecordsAreTheRedemptionsAlone`,
  `testACodeAdmittedOutsideItsRedemptionRenewsNothingAndStaysUnspent`, `testAJobsRedemptionReportsNoClient`
- `tests/Integration/Sso/LinkRedemptionTest.php` `testTheCallerIsLinkedStandalone`,
  `testACodeStartedForAnotherIdentityLinksNobody`, `testACallerThatCannotBeNamedThrowsBeforeTheCodeIsTouched`,
  `testAnApplicationThatIsNoSessionGuardThrowsBeforeTheCodeIsTouched`, `testSsosDefaultFreshnessRefusesEveryLink`, `testAConcurrencyFailureIsRedeemedAgainStandalone`,
  `testTheLastAttemptsFailureReachesTheCaller`,
  `testTheLastAttemptsFailureInANestedTransactionReachesTheCallerAsTheDatabaseRaisedIt`,
  `testAFailureThatIsNoConcurrencyFailureIsNotRetried`, `testAFailureOnceTheAttemptHasCommittedIsNotRedeemedAgain`,
  `testInsideTheCallersTransactionTheLinkCommitsWithIt`,
  `testInsideTheCallersTransactionAConcurrencyFailureLeavesTheCodeUnspent`,
  `testInsideTheCallersTransactionAFailureReachesTheCallerAsItsRetryRecognisesIt`
- `tests/Integration/Sso/RedemptionLockOrderTest.php` (MySQL and PostgreSQL at READ COMMITTED and REPEATABLE READ)
  `testASignInTakesSsosLocksThenTheConnectionGuardThenTheSession`, `testAReauthenticationLocksTheSessionLast`,
  `testASignInRacingAConnectionDisableNeverSignsIn`, `testASignInRacingALinkRemovalNeverSignsIn`,
  `testTwoReauthenticationsRacingForOneSessionBothRenew`, `testALinkTakesTheIdentitysGuardFirst`,
  `testALinkRacingAHolderOfTheIdentitysGuardIsRedeemedAgain`,
  `testASignInWhoseLastAttemptFailsToSerialiseThrowsTheDatabasesFailure`,
  `testAReauthenticationWhoseLastAttemptFailsToSerialiseThrowsTheDatabasesFailure` (on PostgreSQL at REPEATABLE READ
  with one attempt, the database's `QueryException`, SQLSTATE 40001, which Laravel's detector recognises, never
  Laravel's `DeadlockException` around it)
- `tests/Integration/Sso/ReauthenticationSessionsAdapterTest.php` `testASessionThroughTheConnectionStandsAsAFlowStarts`,
  `testASessionOfAnotherGuardStandsAsAFlowStarts`, `testAFlowsStartLocksAndWritesNothing`,
  `testTheLockedStandingLocksTheSessionsRowUntilTheTransactionEnds`, `testASessionWithoutLockedStandingIsNotSignedIn`,
  `testTheLockedStandingOutsideATransactionThrows`, `testTheRenewalIsRecordedAndNothingIsWritten`,
  `testASecondRenewalIsRefused`, `testARenewalNoRedemptionWouldWriteIsRefused`
- `tests/Integration/Sso/ExternalIdentityLinksAdapterTest.php` `testTheAdmittedLinkAnswersForExactlyItsResult`,
  `testAnyOtherResultIsLinkedToNothing`, `testAnExternalSignInGoesThroughTheAdmittedLink`,
  `testAnExternalSignInThroughAnyOtherLinkIsRefused`
- `tests/Integration/Sso/SessionRevocationAdapterTest.php` `testAConnectionsSessionsAreRevoked`,
  `testAConnectionsRevocationFollowsAuthenticationsSwitch`, `testARemovedLinksSessionsAreRevoked`,
  `testAWidenedScopesSessionsAreRevokedWhateverTheSwitchSays`,
  `testAWidenedScopeRevokedTwiceRevokesNothingTheSecondTime`,
  `testAnEnforcementChangeRevokesTheSessionsThePolicyNoLongerAllows`,
  `testAnUnresolvedTenantThrowsAndTheChangeRollsBack`, `testAnIncompleteScopeIsRefused`,
  `testARevocationRollsBackWithTheCallersChange`
- `tests/Integration/Sso/RevocationThroughSsoTest.php` `testAConnectionsChangeEndsItsSessions`,
  `testAConnectionsChangeFollowsAuthenticationsSwitch`, `testRemovingALinkEndsExactlyItsSessions`,
  `testARevocationThatThrowsRollsSsosChangeBack`
- `tests/Integration/Sso/IdentityReferencesTest.php` `testAPersonIsNamedByItsAliasThroughTheMorphMap`,
  `testAClassNameIsNotTheAliasTheMorphMapNames`, `testAnIdNoPersonHoldsResolvesToNobody`,
  `testAStringOrUuidKeyedIdentityResolvesFromItsOwnReference`,
  `testAStringKeyIsNotResolvedFromAnIdItIsNotByteForByte`, `testAUuidKeyIsNotResolvedFromItsUpperCase`,
  `testAnIdentityThatCannotBeNamedThrows`; `tests/Integration/Tenancy/TenantReferencesTest.php`
  `testTheResolversTenantOfTheIdIsTheTenant`, `testATenantOfAnotherIdentifierIsRefused`,
  `testTheResolversReadIsPinnedToTheWriteConnection`
- `tests/Unit/Sso/ExternalResultsTest.php` `testASignInsResultTakesEveryValueFromTheRedemption`,
  `testTheProviderContextIsTheCapturedProvenance`, `testAReauthenticationsResultTakesTheRenewal`;
  `tests/Unit/Sso/AdmittedRedemptionsTest.php` `testOnlyAnAdmittedLinkedRedemptionIsRecorded`,
  `testASecondRedemptionIsRefused`; `tests/Unit/Sso/RenewalRecorderTest.php` `testASecondRenewalIsALogicException`,
  `testARenewalWhileClosedIsALogicException`;
  `tests/Unit/Sso/BoundLinkStorageTest.php` `testTheLinkerBoundAtTheCallAnswers`,
  `testALinkerThatIsNoStorageIsALogicException`; `tests/Unit/Sso/RedemptionSecretsTest.php`
  `testNoFrameOfAThrownTraceHoldsTheSecretsInTheClear`
- `tests/Performance/Sso/SignInRedemptionQueryBudgetTest.php` `testALinkedSignIn`, `testARefusalOfAnUnknownCode`

## Change Triggers

Update this note when:

- a member renames, adds or removes one of the seams in the table, changes a default's class or binding style, or SSO
  starts binding `LinkStorage` or stops finding it through the bound `Linker`;
- `laravel-sso` adds the application to `ReauthenticationSessions::standing()` (the adapter then asks that guard
  alone), or `laravel-authentication`'s `externalStanding()` gains an application parameter (IAM-13.8);
- `laravel-sso` lists the tenants that inherit an enforcing tenant's rule, or the application's tenant tree arrives
  (M6), so the tenant revocation covers them;
- `laravel-authentication` gains a public identity resolver or key-shape check (`IdentityReferences` then uses it);
- either member ships a contract kit for one of these seams (IAM-8.3);
- a member changes the lock order, adds a lock to a redemption (the requirements' authorisation request lock among
  them), changes which refusals it answers and which it throws, or changes what a `RedemptionResult`, `ExternalResult`,
  `Provenance` or either `ClientContext` carries;
- SSO's `admit()` or `redeem()`, `signInExternally()` or `reauthenticateExternally()` changes its parameters;
- freshness, link eligibility or the tenant authentication policy are bound (M5, M6), which changes what a link and an
  enforcement change do;
- the rate-limit counters move off the storage connection by default, which changes what an authentication refusal
  rolls back.
