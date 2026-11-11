# SSO Redemption and Revocation

## Purpose

This note describes how the package joins `laravel-authentication` and `laravel-sso` for redeeming SSO's handoff codes
(IAM-4.1 sign-in, IAM-4.2 re-authentication, IAM-4.3 links), for ending sessions when SSO changes what they rest on
(IAM-4.4) and for SSO's own link store (IAM-4.9), and how SSO's judgements are answered from `laravel-authentication`
and `laravel-mfa`: the provider's evidence through two gates (IAM-4.6, IAM-5.1), freshness and the application's
external sign-in (IAM-4.6), link e-mail matching (IAM-4.7), link confirmation (IAM-4.10) and the `sso` namespace of the
authentication context (IAM-4.8). It covers the seams `Sso\SsoSeams` binds, the three redemption services the
application calls, the records they keep for one request, the transaction and the lock order each runs in, which
refusals commit and which roll back, how SSO's identity and tenant references are resolved, and the gaps in the members
the adapters work around. The tenant authentication policy SSO's enforcement is folded into is described in
`tenant-authentication-policy.md`; link eligibility, tenant membership and principal scope (IAM-7.4, IAM-6.8), the
tenant tree and scope widening's trigger, and provisioning, are described in `provisioning-and-tenancy.md`; the binding
rule that applies every row is in `binding-precedence.md`, and the storage connection and retry helper the redemptions
run through are in `storage-and-transactions.md`.

## Invariants

- `Sso\SsoSeams` declares every binding, and the binding rule applies them in `register()`. Each row replaces only its
  member's own default, and a binding the application made before or after the members register is kept (IAM-8.4).

  | Member seam                         | Bound to                          | Member default replaced       | Lifetime  |
  | ----------------------------------- | --------------------------------- | ----------------------------- | --------- |
  | SSO `ReauthenticationSessions`      | `ReauthenticationSessionsAdapter` | `NoReauthenticationSessions`  | transient |
  | SSO `SessionRevocation` (mandatory) | `SessionRevocationAdapter`        | `NoSessionRevocation`         | transient |
  | AUTH `ExternalIdentityLinks`        | `ExternalIdentityLinksAdapter`    | `NoExternalLinks`             | transient |
  | SSO `Linker`                        | SSO's `Links\LinkStore`           | `NoLinks`                     | scoped    |
  | AUTH `ExternalEvidencePolicy`       | `ExternalEvidencePolicyAdapter`   | `InsufficientEvidence`        | transient |
  | SSO `Freshness`                     | `FreshnessAdapter`                | `RefusingFreshness`           | transient |
  | SSO `ApplicationPolicy`             | `ApplicationPolicyAdapter`        | `ConfiguredApplicationPolicy` | transient |
  | SSO `LinkEmailMatcher`              | `LinkEmailMatcherAdapter`         | `NoEmailMatches`              | transient |
  | SSO `LinkConfirmation`              | `LinkConfirmationAdapter`         | `RefusingLinkConfirmation`    | transient |
  | SSO `EvidencePolicy` (opt-in)       | SSO's `ConnectionEvidencePolicy`  | `InsufficientEvidence`        | scoped    |

  The `sso` namespace of the authentication context is no seam: `SsoContextContributor` is registered with
  `laravel-authentication`'s `ContextContributors` under `sso` from a `booted()` callback `IamServiceProvider::boot()`
  queues, once every provider has booted, under the same switch, as it read when the binding rule ran in
  `register()`: a later provider that turns the switch over comes too late for the bindings and for the contributor
  alike, so the two never disagree.

- Session revocation is mandatory always (IAM-4.4): left on SSO's default, an enforcement change, a disabled or
  deleted connection, a removed link or a widened scope would leave every session it concerns standing. The external
  identity links and the linker are mandatory while SSO is in use (a protocol switched on, or its
  switch malformed, `SsoSeams::isInUse()`, as SSO's `Features::isInUse()` reads it): left on their defaults, or
  unbound, no sign-in through SSO finds its identity and no link is made. The re-authentication sessions are mandatory
  while SSO's enforcement is on or the application names or binds a tenant MFA requirement (IAM-10.2): left on SSO's
  default then, nobody held to a tenant's rule could renew a session through the connection the rule names. Each
  mandate is read by `iam:check` whatever `iam.adapters.sso` says (`install-and-check.md`).
- The whole capability is switched by `iam.adapters.sso` (`IAM_ADAPTERS_SSO`), read in `register()` and leniently, as
  `iam.adapters.mfa` is: `false` (as a boolean or as text), `0`, `off` and `no` turn it off, and anything else, a
  missing or empty value included, leaves it on. Off, nothing here is bound and each member keeps its own default.
- SSO's `HandoffIssuer` is never declared: SSO issues and redeems its own handoff codes, so it stays on
  `Handoffs\DatabaseHandoffStore` in every provider order and with the switch off, and no `HandoffRecheck` is used.
- Links are SSO's: `laravel-authentication` stores none. `Linker` is bound to SSO's own `Links\LinkStore`, which SSO
  also reads as its link storage (SSO's `LinkStorageBinding`). It is scoped under this package's scoped prefix,
  forgotten by `Iam::resetWorkerState()` (IAM-8.1).
- The provider's evidence passes two gates, and neither is the other (IAM-4.6, IAM-5.1, SSO-8.7):
  - The first is SSO's evidence contract, asked at redemption. It stays on SSO's default, which accepts nothing, unless
    `iam.sso.evidence` (`IAM_SSO_EVIDENCE`) is on as well as the capability, read strictly (only `true`, `1`, `on` and
    `yes`): then it is SSO's own `Evidence\ConnectionEvidencePolicy`, which accepts what each connection's evidence
    settings list within `sso.linking.evidence_max_age_seconds`, bound scoped as SSO binds it. An evidence policy the
    application binds is kept either way. Only what it accepted reaches `laravel-authentication`
    (`ExternalResults`), never the result's raw authentication context.
  - The second is MFA's combination policy, which `ExternalEvidencePolicyAdapter` asks about the sign-in's first factor
    as MFA records it: a `first_factor` proof by the `external_provider` method on an `external_provider` channel naming
    the connection, observing nothing, made at the evidence's time, bound to the identity and the application for the
    sign-in no session key names (`SignIn::UNNAMED`). MFA's default classifies nothing a provider reports, so by
    default a provider's `mfa` is never multifactor authentication, an additional verification, a level or phishing
    resistance; an application trusts a provider by rebinding MFA's combination policy to trust its connection. MFA's
    proof carries no `amr`, so a rebound policy trusts the connection, never the methods.
  - `accepts()` counts evidence only as exactly what SSO accepted in the redemption admitted in this request through
    the subject's connection, for the identity that redemption linked (`AdmittedRedemptions::acceptedEvidence()`: its
    methods in order, its raw context, and its time as `laravel-authentication` judges it at the subject's time, to the
    whole second and dated at the subject's time when it is after it), then as MFA's policy finds it credible for the
    probe requirement. Evidence handed to `laravel-authentication` by any other path, for another identity, of another
    time, or once the redemption is over, is never accepted, so nothing is recorded.
  - `meets()` asks MFA's policy for the whole requirement, each part within its maximum age; for a tenant, the
    connection must also be one the tenant trusts: its own (SSO's connection records its tenant) or one its
    enforcement on the application names (`Contracts\Enforcement::policy()`), read on the write connection only once
    MFA's policy has answered met (`ConnectionTrust`). A requirement that asks for nothing is never met nor accepted
    for. Neither method locks or writes, so both may be asked under the session's row lock.
  - Every SSO sign-in records its first factor on the connection's `external_provider` channel, whatever SSO accepted,
    and the session-proof paths would otherwise hand that channel to MFA's combination policy with no gate at all. So
    the proof translator names the connection to MFA only as `Mfa\Translation\ProviderTrust` allows (Decision,
    M9). MFA's own judgements of a session (the proof store and the first-factor resolver behind MFA's route gate,
    the additional-factor policy at sign-in, a pending session's context and the reauthenticator) are asked with
    `ProviderTrust::accepted()`: the connection is named only for a proof carrying evidence SSO's evidence contract
    accepted (`RecordedProof::$evidence`) and, for a session acting in a tenant, from a connection that tenant trusts
    (`ConnectionTrust`). `laravel-authentication`'s requirement check is asked with `ProviderTrust::withheld()`: it is
    told neither the tenant whose requirement it is nor what SSO accepted, and `laravel-authentication` asks its
    external evidence policy (`meets()`, with that tenant) first, so the provider's proof there names no connection.
    A combination policy that trusts a connection therefore counts nothing SSO's evidence gate refused, and one
    tenant's trust in a connection never meets another tenant's requirement. The cost is that such a policy cannot
    combine a trusted provider's first factor with a further factor in `laravel-authentication`'s check; MFA's route
    gate still can, once SSO accepted the evidence.
  - A `reauthenticate` redemption records, through `laravel-authentication`, an `external_reauthentication` proof by
    the `external_provider` method for the `reauthenticate` purpose on a channel naming the connection, which MFA reads
    as a `first_factor_reauthentication` for its own `reauthenticate` purpose, never as a sign-in's first factor. A
    `link` redemption records no proof.
- SSO's freshness (`FreshnessAdapter`, IAM-4.6, SSO-2.12) asks `laravel-authentication`'s freshness policy for the
  operation SSO names (`sso.link.create` and the rest, valid operation names there) with SSO's maximum age as the
  caller's requirement (`FreshnessRequirement::within()`), so the stricter of it and whatever the application configures
  applies. It is `fresh` only when the policy finds a proof that meets it. SSO hands the contract the caller the action
  is taken for (`Identities\Caller`: an identity reference and, when supplied, a session id), and the adapter judges
  that caller alone, never the request, the default guard or the session a guard serves: the session the caller names,
  found among its identity's own sessions on the write connection (`CurrentSession::owned()`), of whichever guard, and
  judged by the policy only while it is live and active. No caller (a queued job, a console command, a call into SSO the
  application hands none), a caller with no session, and a session that is not the identity's are `stale`, however fresh
  the session the request is served with; an identity reference that names no identity throws
  `UnresolvedReferenceException`. The application names its caller as SSO takes it with `Iam::callers()->of($caller)`
  (`Callers`), from `laravel-authentication`'s `Caller` (`Auth::caller()`): its guard resolved as one that holds
  sessions, its identity named as `IdentityReferences::reference()` names it, and the session its access credential
  holds while it is a session of the caller's guard that the caller's identity owns (`Caller::owns()`); a refresh or
  pending credential, or a session of another guard or identity, is named with none. `LinkRedemption` names its caller
  the same way. The policy is asked plainly, never current: SSO asks inside its own transactions, a `link`'s after its
  link locks and before the application's eligibility and confirmation contracts, whose guards come before the session's
  row, and a current judgement would lock the session's row there. A plain read is trusted only from a transaction
  opened after the caller was named, such as SSO's own, whose snapshot is no older than the call: a caller named while a
  transaction is already open on the storage connection (a `link` redeemed inside the caller's transaction) is named
  with no session, and so is `stale` without the policy being asked, since that snapshot may still count a proof voided
  or a session revoked before the call.
- SSO's link confirmation (`LinkConfirmationAdapter`, IAM-4.10, SSO-8.8) answers from how the caller's session was
  signed in, read through `laravel-authentication`'s public readers of a session's proofs and provenance (IAM-13.9,
  `Auth::sessions($guard)->firstFactor()`, `proofs()` and `provenance()`), and never from `Auth::context()` keys
  (Decision Q13 (a)). The
  session judged is found exactly as freshness finds it: the session the caller SSO hands over names, among its
  identity's own (`CurrentSession::owned()`), read through the reader of the guard it belongs to; SSO has checked that
  the caller's identity is the one the code is bound to. It is `independent` only when the session's first factor, the
  oldest counting first-factor proof, was made over the `password`, `passkey` or `recovery` channel (the application's
  own recovery, a `start()` from a first factor on that channel, which `laravel-authentication` admits as a first factor
  only), the session holds no counting `external_reauthentication` proof, and its recorded provenance names no link
  of verified domain provenance (SSO's `link_provenance` in the provider context). Everything else is `dependent`: an SSO
  session, whichever link it stood on, a code sign-in, any other `start()`, a first factor that no longer counts, a
  pending, revoked or ended session (the reader answers none), a caller with no session, a session that
  is not its identity's or is of a guard that holds no sessions, and any judgement outside a transaction. SSO asks it
  inside a `link` redemption's transaction, after the application's eligibility; there the reader locks the session's
  row until the transaction ends and reads its proofs and provenance current, so the answer holds until the redeemer
  commits by the
  lock every writer of the session takes first (SSO's "guard writers of sessions take"), and the session's row is the
  last lock in SSO's order. Outside a transaction nothing can hold it true, so the answer is `dependent` without a read.
  Unlike freshness, a caller named inside the caller's own transaction needs no rule of its own: the read is current,
  never the snapshot's, and at PostgreSQL's REPEATABLE READ a session changed since the snapshot fails to serialise for
  the transaction to be retried; such a caller is named with no session for freshness's sake, so it is `dependent` here
  too, and such a `link` is refused for freshness first in any case. SSO's rule is phrased by the session's link
  provenance (`sso.link_provenance`): `laravel-authentication` records a provenance only for a session an external
  provider established, whose first factor is on the `external_provider` channel, so every session with one is already
  `dependent` by its first factor (Decision, M10). The provenance is read as well, so a session is never `independent`
  while its record names a link of verified domain provenance, but it never makes a session `independent` on its own: a
  session through a link of no verified domain provenance is `dependent` too, since FEATURES (IAM-4.10) names only a
  password, a passkey and the application's recovery, stricter than SSO's contract, never looser. A provider context
  SSO's `Provenance::restore()` cannot read back throws `UnexpectedValueException`, never read as none. The connection
  and the domain link ids SSO hands over are not read: no session the adapter answers `independent` for stood on any
  link. The adapter is not mandatory: SSO's default
  refuses every `link` it is asked about.
- SSO's application policy (`ApplicationPolicyAdapter`, IAM-4.6, SSO-5.1) answers `allowed` exactly when
  `laravel-authentication`'s application policy lets the guard of the application's name start sessions by the
  `external_provider` method; SSO's own `external_sign_in` setting is not read. A guard `laravel-authentication` does
  not know is its `InvalidArgumentException`, which propagates.
- SSO's link e-mail matcher (`LinkEmailMatcherAdapter`, IAM-4.7, SSO-8.8) puts the asserted e-mail through
  `laravel-authentication`'s `email` normaliser and nothing more (no subaddress or dot removal, Unicode folding or
  confusable matching), and searches each identity model a session guard's provider names that reports its
  identifiers' verification, once each, for that normal form, on the write connection with the model's own query. A
  row counts only when the identity reports its e-mail verified and the address is the normal form byte for byte. One
  is `exactly one`, none is `none`, more than one is `ambiguous`; an e-mail the normaliser refuses names nobody without
  a query. It takes no lock and relies on the application's uniqueness of a verified e-mail (or a guard every writer
  takes after SSO's locks); the tenant SSO names is link eligibility's to judge (IAM-7.4), not the matcher's.
- The `sso` namespace (`SsoContextContributor`, IAM-4.8, SSO-9.7): the contributor reads the stored form a sign-in
  handed `laravel-authentication` as the provider context (`$subject->provenance()?->providerContext?->toArray()`),
  projects it through SSO's `AuthenticationContext::fromStored()` and answers each key without its `sso.` prefix. No
  stored form contributes no key; a stored form contributes all twelve, `null` where the sign-in stated nothing. A
  stored form SSO cannot restore (`UnexpectedValueException`), a provenance `laravel-authentication` cannot read and a
  database error propagate. It is registered once, while the capability's switch is on as the binding rule read it in
  `register()` (a value a later provider writes changes neither), from a `booted()` callback,
  so once every provider has booted (at once when the application already has): a member may be registered from
  another provider's `boot()`, after this package's has run, and `laravel-authentication` binds its contributors only
  as its provider registers, so a registration from this package's own `boot()` would go to an instance the container
  builds and nobody keeps, and be lost without a word. A contributor the application registered under `sso` before
  the application finished booting, from any provider's `boot()`, is kept, and one registered once it has booted is
  `laravel-authentication`'s `LogicException`. A re-authentication records no provider context, so it never changes
  the keys.
- One core method for each action, taking plain values:
  - `SignInRedemption::redeem(string $application, string $connectionId, string $code, string $verifier,
    SignInContext $context): RedemptionResult|SignInResult`. It takes `laravel-authentication`'s `SignInContext`, not
    a bare `ClientContext`, because `signInExternally()` requires one: the caller's principal, tenant selection, client
    name and deadline reach the sign-in unchanged, and SSO's client is built from `$context->client`.
  - `ReauthenticationRedemption::redeem(string $application, string $connectionId, string $code, string $verifier,
    ClientContext $client): AccessTokenResult|RedemptionResult`.
  - `LinkRedemption::redeem(string $connectionId, string $code, string $verifier, ClientContext $client,
    Caller $caller): RedemptionResult`. The caller is handed over as `laravel-authentication`'s `Caller`, which the
    application reads where it reads the request (`Auth::caller()`); its guard is the application, its identity the
    one linked, and its session the one SSO's freshness and link confirmation judge, handed to SSO as SSO's own caller
    (`Callers::of()`). It is never read from `Auth::identity()`, the guard's current session nor the request's body.
  - `Callers::of(Caller $caller): Identities\Caller` (`Iam::callers()`) names the caller of the application's own call
    into SSO (a management helper, a link's removal, a `link` flow's start) as SSO takes it. It is a translation, not an
    action: SSO's helpers and starts take the caller themselves, so this package keeps no scope around them.
  - The code and the verifier are `#[\SensitiveParameter]`. The `ClientContext` is `laravel-authentication`'s, built
    with `ClientContext::fromRequest()` or `SignInContext::fromRequest()` where the request is read, or as
    `new ClientContext(null, null)` from a job or a command, whose events then carry no IP address or user agent. SSO's
    own `ClientContext` is built from it in one place (`Sso\Translation\ClientTranslator::toSso()`), with the IP address
    and user agent, the two values SSO's carries.
  - The application reaches each service through an accessor of the manager and the facade (`Iam::signIns()`,
    `Iam::reauthentications()`, `Iam::links()`), never through a second method that repeats one's signature. No
    service, adapter or record reads a request, a cookie, a header, the guard's current user or its current session:
    SSO's freshness and link confirmation contracts judge only the caller SSO hands them (above).
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
    `IamServiceProvider::registerCommitListeners()`); an attempt during which the storage connection's count moved
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
  the link SSO resolved and the client SSO was handed for it (which the tenant authentication policy hands SSO's
  exemption gate while that sign-in or re-authentication is judged, `tenant-authentication-policy.md`),
  `RenewalRecorder` at most one renewal, `Transactions\OutermostCommits` the outermost commits each connection has
  begun, and `Transactions\CommittedWork` the work held until a connection's commit has finished (an enforcement
  change's second pass, and a reported policy change's). All four are bound scoped under
  `BindingRule::SCOPED_PREFIX` and resolved through that key (`IamServiceProvider::registerRedemptionRecords()`), so
  the worker reset forgets them, and every adapter, listener and redemption resolves them from the container on each
  call. Each commit listener, and the `iam` manager (`IamManager`), resolves what it calls from the application
  current when it runs (`Container::getInstance()`), never from a container kept since: under Octane the events
  dispatcher, and the manager when it was resolved before the worker cloned the application, belong to the worker's
  own application, while each request's records are its sandbox's. Each redemption forgets the admitted redemption
  and the renewal as each attempt starts and again as it ends, so a retried attempt never meets a record of one rolled
  back, and nothing later in the request answers from a redemption that is over.
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
  | `tenant` (`enforcement_changed`)       | `tenantPolicyChanged($tenant)`, twice       | none (mandatory)           |
  | `connection` (`connection_disabled`)   | `connectionDisabled()`                      | `laravel-authentication`'s |
  | `connection` (`connection_deleted`)    | `connectionDeleted()`                       | `laravel-authentication`'s |
  | `identity_connection` (`link_removed`) | `linkRemoved()`                             | `laravel-authentication`'s |
  | `identity_link` (`scope_widened`)      | `linkScopeWidened()`, never `linkRemoved()` | none (idempotent)          |

  Each helper runs as a savepoint of SSO's transaction on the shared connection, throws on failure, and reports a
  revocation only once SSO's change commits, so nothing is reported that was not done. A connection scope with any
  other reason, and a scope missing what its kind names, throws a `LogicException`. The tenant scope's helper runs a
  second time once SSO's transaction commits, as `laravel-authentication` asks for a strict cut-off (Decision, M5:
  the second pass is held for the storage connection's own transaction and runs once every callback queued on it has
  run, SSO's report of the change among them, or, when one of those callbacks fails, as the unit of work ends; see
  Failure / Edge Cases). Both passes go through `laravel-authentication`'s `tenantPolicyChanged()` as
  `Tenancy\TenantPolicyChanges::changed()` makes them, the application's own reports included
  (`tenant-authentication-policy.md`); for the enforcement change they are made for the enforcing tenant's subtree by
  `Tenancy\SubtreePolicyChanges`, whose pass after the commit lists the subtree again (`provisioning-and-tenancy.md`).
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
   evidence was accepted. The token issued, `laravel-authorization` forgets the request's decisions, naming the
   session and SSO's reference to the identity (`DecisionCacheInvalidation`, IAM-6.11, `authorization.md`), and again
   should the transaction roll back. No renewal is still recorded when it commits, and the token leaves after the
   commit.
3. Link: `Iam::links()->redeem(...)` resolves the caller's guard, names its identity to SSO and calls SSO's
   standalone `redeem()`, which commits the link before it answers (inside a transaction the caller holds open, it
   writes the link in a savepoint of that transaction instead); no session is written.
4. Revocation: an SSO change (a connection disabled or deleted, a link removed, a scope widened, an enforcement change)
   calls `revoke()` inside its own transaction; the adapter resolves the identity or tenant and ends exactly the
   sessions the scope names, which commit, or roll back, with SSO's change; an enforcement change's tenant is judged
   once more when that commits.

## Failure / Edge Cases

- SSO's refusal (an unknown code, a mismatching verifier, a replay, `session_ineligible`, `identity_mismatch` and the
  rest) is answered as the `RedemptionResult`, and commits: a code SSO consumed stays spent, and one `FlowFailed`
  follows the commit. A rate-limited redemption is answered the same way.
- `laravel-authentication`'s refusal rolls back: a failed `SignInResult` throws `ExternalSignInRefusedException` and a
  failed `AccessTokenResult` throws `ExternalReauthenticationRefusedException`, each carrying the result, so the code
  stays unspent, no reservation is activated and no `HandoffRedeemed` or `ReauthenticationCompleted` is reported.
  `laravel-authentication`'s own report of the refusal (`AuthenticationFailed`), dispatched at once inside the
  transaction, is recorded in the audit trail once the transaction has rolled back, never inside it
  (`Audit\DeferredRefusals`, see `audit-mapping.md`). A result naming another link than the session's is
  `link_mismatch`, and rolls back the same way, and so does a session write that throws, which reaches the caller as
  it was thrown, undoing the connection's first completed sign-in SSO acknowledged in the transaction with the
  consumption. SSO counts the attempt on the storage connection unless
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
  binds a tenant resolver. `tenantPolicyChanged()` judges every session acting in the tenant against the tenant
  authentication policy this package binds (`tenant-authentication-policy.md`), SSO's enforcement as it now answers
  folded in with its exemption gate and the application's tenant MFA requirement: a session through a satisfying
  connection, or an exempt identity's, stays, and every other active one the first pass locks is revoked in SSO's
  transaction. Those are the sessions committed when it reads them: a password or passkey sign-in, a switch into the
  tenant, or a sign-in through another tenant's connection takes no lock of SSO's rule, so one that judged the policy
  before the change and commits its session while the change runs is not among them (on MySQL at REPEATABLE READ the
  first pass's gap lock holds its write until the change commits). So the adapter, through
  `Tenancy\SubtreePolicyChanges`, holds a second `tenantPolicyChanged()` for the storage connection
  (`Transactions\AfterConnectionCommits`, for that connection's own innermost transaction, never another
  connection's), which runs once the outermost transaction there commits, for the tenant resolved anew, skips
  every session the first pass recorded at the version it answered, and revokes the sessions that entered the tenant
  meanwhile; a rollback callback of the transaction it was queued in drops it when the change rolls back. It runs only
  once every callback queued on that transaction has run: SSO queues its report of the change (`EnforcementChanged`)
  after the revocation, and drops an event whose callback finds an outermost transaction begun after the one it was
  queued in (its `TransactionGenerations`), so a second pass run from a commit callback, which opens a transaction,
  would leave every enforcement change unreported. It is held instead (`Transactions\CommittedWork`), from the moment
  it is queued, for Laravel's `TransactionCommitted` event, which the connection fires once every callback has run, and
  is released only by a commit that leaves no transaction open on the connection, never a savepoint's (a connection
  with no events dispatcher fires none, and there a commit callback releases it). A commit callback that fails, queued
  before it (the first pass's own revocation reports) or after it (a synchronous listener of `EnforcementChanged`),
  stops Laravel running the rest, and the connection then fires no `TransactionCommitted`: the change is durable, the
  callback's failure propagates from `EnforcementService::update()`, and the second pass stays held until the unit of
  work ends, where it runs (`AfterConnectionCommits::settle()`: the application's termination, at the end of a request
  or a console command, a queued job's end, `JobProcessed` or `JobExceptionOccurred`, and `Iam::resetWorkerState()`),
  or until the connection's next outermost commit in the same unit of work, whichever comes first; what it throws there
  is reported, the caller's own work being over. A session that entered the tenant meanwhile acts on its access tokens
  until then. What it throws from the commit propagates, out of `EnforcementService::update()`, once the change is
  durable and SSO has reported it: the rule stays changed, the first pass's revocations stand, and the sessions only the
  second pass would have judged wait for the next `tenantPolicyChanged()` or their first refresh. Each pass asks the
  policy for an exempt identity's session, so its exemption is reported once by each. A sign-in that judged the policy
  before the change committed and writes its session only after the second pass has run is judged at its first refresh
  (a member gap, below).
  SSO names only the enforcing tenant and cannot list the tenants that inherit its rule, so the tenants below it come
  from the application's tenant tree: with one configured, the sessions of the enforcing tenant and of every tenant
  below it are judged, each resolved before any is (`Tenancy\SubtreePolicyChanges`, `provisioning-and-tenancy.md`),
  broader than the tenants that inherit and never narrower; without one, only the enforcing tenant's. The second pass
  then lists and resolves the subtree again from the tree as it stands after the commit, rather than judge the tenants
  the first pass listed, so a tenant moved under the enforcing tenant while the change was open is judged against the
  rule that has committed.
- A `link` whose caller signed in longer ago than SSO's maximum age for `sso.link.create` (300 seconds by default) is
  refused as `freshness_required` under SSO's locks, and so is one whose caller holds no session of its own, and one
  redeemed inside the caller's own transaction, whose snapshot may be older than the redemption. A `link` flow
  started for a caller with no session (`Iam::callers()->of()` names none inside a transaction) is refused for
  freshness at its start. A plain read inside
  SSO's own transaction may answer as of its snapshot, which a `link` redemption takes as it starts, a moment before.
  Link eligibility is answered from the application's memberships (`Tenancy\LinkEligibilityAdapter`,
  `provisioning-and-tenancy.md`) once they are named or bound; without them SSO's default refuses every link
  (`link_ineligible`). The redemption tests stand in a fixture that lets everyone link where eligibility is not their
  subject, and SSO's `Testing\FakeFreshness` where freshness is not.
- Evidence from a connection a tenant does not trust never meets that tenant's requirement, however MFA's policy judges
  it; a tenant whose identifier is neither a non-empty string nor an integer throws
  `UnresolvedReferenceException(tenant)`, and an identity whose key cannot be named throws, inside
  `laravel-authentication`'s transaction (IAM-8.2).
- Two identities holding the same verified e-mail make linking by a verified domain `ambiguous`, which SSO refuses;
  an e-mail a case- or accent-insensitive collation merely matches is no match.
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
    inherit its rule: the adapter judges every tenant below it in the application's tree, so without a tree (an
    inheritance of the application's own) those tenants are left unjudged.
  - `laravel-authentication`'s sign-ins and switches judge the tenant authentication policy with plain reads and take
    no lock a policy change waits on, and `tenantPolicyChanged()` judges only the sessions committed when it reads
    them, so even its second pass, after the change commits, misses a sign-in that judged the policy before the change
    committed and writes its session after that pass has run; the session stands, on its access tokens, until its
    first refresh judges it. Only a recheck of the policy's version as the session is written would close it.
  - `laravel-authentication` has no public helper to resolve an identity from a morph type and key or to check a key's
    shape; `IdentityReferences` reuses `SessionKeyShape::matches()`, which works on any model.
  - Neither member ships a contract kit for `ReauthenticationSessions`, `SessionRevocation`, `Linker`/`LinkStorage` or
    `ExternalIdentityLinks`, so IAM-8.3 has none to extend here.
  - `laravel-sso` asks freshness inside its transactions before the guards that come before the session's row in its
    lock order, and `laravel-authentication`'s policy can judge as committed only by locking that row, so the adapter
    cannot judge current there: it trusts a plain read only from a transaction opened after the caller was named, so
    a caller named inside a transaction carries no session, and a `link` inside the caller's own transaction is
    `stale`.
  - `laravel-mfa`'s `Proof` carries no provider methods, so a rebound combination policy can trust a provider only by
    its connection, not by the methods SSO accepted.
  - `laravel-authentication` has no public lookup of an identity by a verified identifier, and the verified-at column
    is protected (`getVerifiedAtName()`), so the matcher filters the rows holding the normal form by
    `hasVerifiedIdentifier()` in PHP, and assumes the identifier is the attribute named after its type.
  - `laravel-authentication`'s `EvidenceSubject` names no tenant's trust in a connection, and its `ExternalEvidence`
    no connection's tenant, so the adapter reads SSO's connection and enforcement for a tenant's requirement.
  - Neither member ships a contract kit for `ExternalEvidencePolicy`, `Freshness`, `ApplicationPolicy`,
    `LinkEmailMatcher` or a context contributor.
  - `laravel-sso`'s guide for this package shows `signInExternally()` without its `SignInContext`,
    `reauthenticateExternally()` without its `ClientContext`, and `Auth::sessions()` with no guard, the default guard
    only; the adapters pass both contexts and use the application's guard.

## Implementation Anchors

- `src/Sso/SsoSeams.php`: `seams()`, `isOn()`, `isEvidenceOn()`, `SWITCH`, `EVIDENCE_SWITCH`;
  `config/iam.php`: `adapters.sso`, `sso.evidence`;
  `src/IamServiceProvider.php`: `registerRedemptionRecords()`, `registerContextContributors()`,
  `registerContributor()`, `registerCommitListeners()`, `seamProviders()`;
  `src/Transactions/OutermostCommits.php`: `committing()`, `count()`;
  `src/Transactions/ConcurrencyFailures.php`: `asRaised()`, what a redemption's last failure reaches the caller as.
- `src/Sso/SignInRedemption.php`, `src/Sso/ReauthenticationRedemption.php`, `src/Sso/LinkRedemption.php`: `redeem()`;
  `src/Sso/ReauthenticationRedemption.php`: `reauthenticate()`, forgetting the request's decisions once it renews;
  `src/IamManager.php`: `signIns()`, `reauthentications()`, `links()`; `src/Facades/Iam.php`.
- `src/Sso/AdmittedRedemptions.php`: `record()`, `matching()`, `acceptedEvidence()`, `clientFor()`, `forget()`;
  `src/Sso/RenewalRecorder.php`: `open()`, `close()`, `record()`, `take()`, `isHolding()`; `src/Sso/Renewal.php`;
  `src/Sso/Callers.php`: `of()`; `src/IamManager.php`: `callers()`; `src/Mfa/CurrentSession.php`: `owned()`.
- `src/Sso/ExternalEvidencePolicyAdapter.php`: `accepts()`, `meets()`; `src/Sso/ConnectionTrust.php`: `trusts()`;
  `src/Mfa/Translation/ProviderTrust.php`: `accepted()`, `withheld()`; `src/Mfa/Translation/ProofTranslator.php`:
  `toMfa()`; `src/Sso/FreshnessAdapter.php`: `check()`;
  `src/Sso/ApplicationPolicyAdapter.php`: `externalSignIn()`; `src/Sso/LinkEmailMatcherAdapter.php`: `match()`;
  `src/Sso/LinkConfirmationAdapter.php`: `judge()`, `INDEPENDENT_CHANNELS`;
  `src/Sso/SsoContextContributor.php`: `contribute()`.
- `src/Sso/ExternalResults.php`: `from()`, `renewing()`; `src/Sso/Translation/ClientTranslator.php`: `toSso()`.
- `src/Sso/ReauthenticationSessionsAdapter.php`: `standing()`, `lockedStanding()`, `renewAuthentication()`;
  `src/Mfa/CurrentSession.php`: `sessions()`, `sessionGuards()`, `identitySessions()`, `isInTransaction()`.
- `src/Sso/ExternalIdentityLinksAdapter.php`: `find()`; `src/Sso/SessionRevocationAdapter.php`: `revoke()`;
  `src/Transactions/AfterConnectionCommits.php`: `run()`, `committed()`, `settle()`, the second pass held for the
  storage connection's own transaction; `src/Tenancy/TenantPolicyChanges.php`: `changed()`;
  `src/Transactions/CommittedWork.php`: `hold()`, `drop()`, `release()`, `connections()`, the second pass held until
  every callback of the commit has run; `src/IamServiceProvider.php`: `registerCommitListeners()`.
- `src/Sso/IdentityReferences.php`: `identity()`, `reference()`; `src/Tenancy/TenantReferences.php`: `tenant()`.
- `src/Exceptions/UnlinkedSignInException.php`, `src/Exceptions/ExternalSignInRefusedException.php`,
  `src/Exceptions/ExternalReauthenticationRefusedException.php`; `src/Exceptions/UnresolvedReferenceException.php`:
  `forGuard()`, `forIdentityReference()`, `forTenant()`.

## Authoritative Tests

- `tests/Feature/Sso/SsoSeamsTest.php` `testTheEvidenceSwitchBindsSsosConnectionEvidencePolicyInEveryProviderOrder`,
  `testTheApplicationsEvidencePolicyIsKeptWithTheSwitchOn`,
  `testTheEvidencePolicyIsScopedAndForgottenWhenTheWorkerResets`,
  `testTheEvidenceSwitchBindsNothingWithTheCapabilityOff`, `testTheEvidenceSwitchIsReadStrictly`
- `tests/Feature/Sso/ContextContributorRegistrationTest.php`
  `testTheContributorsAreRegisteredInEveryProviderOrder`, `testTheSwitchOffRegistersNothing`,
  `testTheSwitchTurnedOffLaterLeavesTheBindingsAndTheContributorOn`,
  `testTheSwitchTurnedOnLaterLeavesTheBindingsAndTheContributorOff`,
  `testAnApplicationsEarlierContributorIsKept`, `testAnApplicationsContributorRegisteredAfterThisPackageBootedIsKept`,
  `testAnApplicationsContributorRegisteredOnceBootedIsRefused`,
  `testTheContributorIsRegisteredWhenAuthenticationRegistersWhileBooting`
- `tests/Integration/Sso/ExternalEvidencePolicyAdapterTest.php` (every isolation level where a sign-in commits)
  `testWithSsosDefaultNoEvidenceReachesAuthenticationOrMfa`, `testWithMfasDefaultAProvidersMfaIsNotMultifactor`,
  `testOnlyARebindingThatTrustsTheConnectionCountsItsMfa`, `testARebindingThatTrustsAnotherConnectionCountsNothing`,
  `testAReauthenticationRecordsAFirstFactorReauthenticationForMfasReauthenticatePurpose`, `testALinkRecordsNoProof`,
  `testAdmittedEvidenceIsCredibleAsMfasPolicySays`,
  `testMfaIsHandedTheSignInsFirstFactor`, `testEvidenceNoRedemptionAdmittedIsNeverAccepted`,
  `testEvidenceOtherThanSsoAcceptedIsNeverAccepted`, `testEvidenceAdmittedForAnotherIdentityIsNeverAccepted`,
  `testEvidenceOfAnotherTimeIsNeverAccepted`, `testEvidenceDatedAfterTheSubjectsTimeIsAcceptedAsOfIt`,
  `testAcceptedEvidenceMeetsARequirementWithinItsMaximumAge`,
  `testARequirementThatAsksForNothingIsNeverMet`, `testATenantTrustsItsOwnConnectionsAlone`,
  `testATenantTrustsTheConnectionsItsEnforcementNames`
- `tests/Integration/Sso/ProviderTrustTest.php` (every isolation level where a sign-in commits)
  `testATrustedConnectionCountsNothingSsoDidNotAccept`, `testEvidenceSsoAcceptedFromATrustedConnectionPassesMfasGate`,
  `testAnAcceptedFirstFactorNamesItsConnectionOnlyForATenantThatTrustsIt`,
  `testWithoutEnforcementATenantTrustsItsOwnConnectionAlone`
- `tests/Unit/Mfa/Translation/ProofTranslatorTest.php` `testAProvidersProofNamesItsConnectionOnlyWithAcceptedEvidence`,
  `testAProvidersProofOnNoConnectionNamesNone`
- `tests/Integration/Sso/FreshnessAdapterTest.php` `testSsosMaximumAgeIsTheCallersRequirement`,
  `testTheApplicationsStricterRequirementApplies`, `testNoCallerIsStale`, `testACallerWithNoSessionIsStale`,
  `testACallerIsJudgedOnItsOwnLiveSessionAlone`, `testACallerNamingNoIdentityThrows`,
  `testOnlyTheSessionAnAccessCredentialHoldsIsNamed`, `testACallerOnAGuardThatHoldsNoSessionsCannotBeNamed`,
  `testACallerWhoseIdentityCannotBeNamedCannotBeNamed`, `testThePolicyIsAskedPlainlyInsideSsosTransaction`,
  `testACallerNamedInsideATransactionCarriesNoSession`, `testALinkIsRedeemedForACallerFreshEnough`,
  `testALinkIsRefusedForACallerNoLongerFresh`, `testALinkWhoseCallerHoldsAnotherPersonsSessionIsRefused`,
  `testALinkInsideTheCallersTransactionIsRefused`, `testALinkFlowStartedForACallerWithNoSessionIsRefused`;
  `tests/Integration/Mfa/CurrentSessionTest.php` `testTheIdentitysOwnSessionIsFoundOfWhicheverGuard`
- `tests/Unit/Sso/ApplicationPolicyAdapterTest.php` `testTheGuardsMethodListAloneDecides`,
  `testAGuardAuthenticationCannotJudgePropagates`
- `tests/Integration/Sso/LinkEmailMatcherAdapterTest.php` `testTheOneVerifiedIdentityIsExactlyOneMatch`,
  `testOnlyAVerifiedAddressMatches`, `testNoAddressIsFoldedIntoAnother`,
  `testAnEmailTheNormaliserRefusesMatchesNobodyWithoutAQuery`, `testTwoVerifiedIdentitiesAreAmbiguous`,
  `testEachKindOfIdentityIsSearchedOnce`, `testEveryHolderOfOneKindIsJudged`,
  `testAnAddressACollationMerelyMatchesIsNoMatch`, `testTheIdentitiesAreReadOnTheWriteConnection`
- `tests/Integration/Sso/SsoContextContributorTest.php` `testASessionThroughSsoContributesEverySsoKey`,
  `testAFactTheSignInDidNotStateIsHeldAsNull`, `testAnyOtherSessionContributesNoKey`,
  `testAnExternalSessionWithNoStoredFormContributesNoKey`,
  `testAReauthenticationLeavesEveryKeyAsItWas`, `testAStoredFormSsoCannotRestoreFailsTheBuild`,
  `testADatabaseErrorFailsTheBuild`
- `tests/Performance/Sso/SsoJudgementsQueryBudgetTest.php` `testALinkEmailMatch`, `testAFreshnessCheck`,
  `testAnApplicationsExternalSignIn`, `testEvidenceMfasDefaultFindsMeetsNothing`
- `tests/Unit/Sso/AdmittedRedemptionsTest.php` `testTheAcceptedEvidenceIsAnsweredForItsConnectionAndIdentityAlone`
- `tests/Feature/Sso/SsoSeamsTest.php` `testEveryAdapterIsBoundOverItsMembersDefaultInEveryProviderOrder`,
  `testTheHandoffIssuerKeepsSsosOwnStoreInEveryProviderOrder`,
  `testAnApplicationBindingMadeBeforeAnyProviderRegistersIsKept`,
  `testAnApplicationBindingMadeOnceEveryProviderHasRegisteredWins`,
  `testTheLinkStoreIsScopedAndForgottenWhenTheWorkerResets`,
  `testTheSwitchOffBindsNothing`,
  `testTheSwitchIsReadLeniently`, `testEachBindingsLifetimeDefaultsAndMandate`
- `tests/Feature/Sso/RedemptionRecordsTest.php` `testTheRecordIsOneInstanceForTheUnitOfWork`,
  `testTheWorkerResetForgetsTheRecord`; `tests/Feature/IamServiceProviderTest.php` `testEachOutermostCommitIsCounted`,
  `testOutermostCommitsAreCountedWithTheWorkerResetOff`, `testHeldWorkRunsOnceTheConnectionCommits`,
  `testWorkACommitLeftHeldRunsAsTheApplicationTerminates`, `testWorkACommitLeftHeldRunsAsAJobEnds`,
  `testTheCommitListenersReachAnOctaneSandboxsRecords`; `tests/Unit/Transactions/OutermostCommitsTest.php`
  `testEachCommitIsCountedForItsOwnConnection`
- `tests/Feature/IamManagerTest.php` `testEachRedemptionIsReachedThroughItsOwnService`,
  `testTheCallersAreNamedThroughTheirOwnService`, `testEachServiceIsResolvedFromTheCurrentApplication`;
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
  `testACodeAdmittedOutsideItsRedemptionRenewsNothingAndStaysUnspent`, `testAJobsRedemptionReportsNoClient`,
  `testARenewalForgetsTheRequestsDecisions`, `testARefusalBySsoKeepsTheRequestsDecisions`
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
  `testAnEnforcementChangeJudgesTheTenantAgainOnceItCommits`, `testTheSecondPassRunsOnceEveryCallbackOfTheCommitHasRun`,
  `testTheSecondPassWaitsForTheStorageConnectionAlone`, `testTheSecondPassStillRunsWhenAnotherCommitCallbackFails`,
  `testAnUnresolvedTenantThrowsAndTheChangeRollsBack`, `testAnIncompleteScopeIsRefused`,
  `testARevocationRollsBackWithTheCallersChange`
- `tests/Integration/Tenancy/EnforcementSecondPassTest.php` (MySQL and PostgreSQL at READ COMMITTED and REPEATABLE
  READ, the session written on another connection once the change's first pass has read)
  `testASessionThatEnteredTheTenantDuringTheChangeIsRevokedOnceItCommits`;
  `tests/Integration/Transactions/AfterConnectionCommitsTest.php` `testWithNoTransactionOpenTheWorkRunsAtOnce`,
  `testTheWorkRunsOnceTheOutermostTransactionCommits`, `testTheWorkRunsOnceEveryCallbackOfTheCommitHasRun`,
  `testWhatTheWorkThrowsPropagatesOnceTheCommitHasFinished`, `testTheWorkIsDroppedWhenItsTransactionRollsBack`,
  `testAnotherConnectionsTransactionNeitherDelaysNorTakesTheWork`, `testWithoutATransactionsManagerTheWorkRunsAtOnce`,
  `testWithoutAnEventsDispatcherTheCallbackRunsTheWork`, `testAFailingCallbackLeavesTheWorkForTheEndOfTheUnitOfWork`,
  `testLeftoverWorkWaitsForTheNextOutermostCommit`, `testTheEndOfTheUnitOfWorkLeavesAConnectionWithATransactionOpen`,
  `testTheEndOfTheUnitOfWorkRunsNothingRolledBack`, `testTheEndOfTheUnitOfWorkReportsWhatTheWorkThrows`;
  `tests/Unit/Transactions/CommittedWorkTest.php` `testAReleaseRunsItsOwnConnectionsWorkInOrder`,
  `testWorkIsReleasedOnce`, `testADroppedPieceIsDroppedAlone`, `testDroppingEveryPieceForgetsTheConnection`,
  `testTheFirstFailureIsRethrownOnceEveryPieceHasRun`
- `tests/Integration/Sso/RevocationThroughSsoTest.php` `testAConnectionsChangeEndsItsSessions`,
  `testAConnectionsChangeFollowsAuthenticationsSwitch`, `testRemovingALinkEndsExactlyItsSessions`,
  `testARevocationThatThrowsRollsSsosChangeBack`
- `tests/Integration/Tenancy/EnforcementThroughTenantPolicyTest.php` (every isolation level where it commits)
  `testASignInNamesTheEnforcementVersionJudgedUnderTheLocks`,
  `testAnEnforcementChangeRevokesTheSessionsTheRuleNoLongerAllows`,
  `testASecondPassThatThrowsLeavesTheChangeDurableAndReported`
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
  `tests/Unit/Sso/RedemptionSecretsTest.php`
  `testNoFrameOfAThrownTraceHoldsTheSecretsInTheClear`
- `tests/Integration/Sso/LinkConfirmationAdapterTest.php` (every isolation level where a redemption or a judgement
  reads inside a transaction) `testTheAdapterIsSsosLinkConfirmation`,
  `testASessionThroughTheDomainLinkCannotConfirmIt`, `testASessionThePersonHoldsApartConfirmsTheLink`,
  `testOnlyAStartedSessionOnTheRecoveryChannelIsIndependent`, `testASessionRenewedThroughAProviderIsDependent`,
  `testASessionRecordingAVerifiedDomainLinkIsDependent`,
  `testACallerHoldingNothingOfThePersonsOwnIsDependent`, `testOutsideATransactionEveryoneIsDependent`,
  `testTheSessionsRowIsLockedUntilTheTransactionEnds`, `testASessionRevokedSinceTheTransactionReadIsDependent`
- `tests/Performance/Sso/SignInRedemptionQueryBudgetTest.php` `testALinkedSignIn`, `testARefusalOfAnUnknownCode`

## Change Triggers

Update this note when:

- a member renames, adds or removes one of the seams in the table, changes a default's class or binding style, or SSO
  starts binding `LinkStorage` or stops finding it through the bound `Linker`;
- `laravel-sso` adds the application to `ReauthenticationSessions::standing()` (the adapter then asks that guard
  alone), or `laravel-authentication`'s `externalStanding()` gains an application parameter (IAM-13.8);
- `laravel-sso` lists the tenants that inherit an enforcing tenant's rule in its tenant scope (the subtree from the
  application's tree may then go), or the tree contract changes;
- `laravel-authentication` gains a public identity resolver or key-shape check (`IdentityReferences` then uses it);
- either member ships a contract kit for one of these seams (IAM-8.3);
- a member changes the lock order, adds a lock to a redemption (the requirements' authorisation request lock among
  them), changes which refusals it answers and which it throws, or changes what a `RedemptionResult`, `ExternalResult`,
  `Provenance` or either `ClientContext` carries;
- SSO's `admit()` or `redeem()`, `signInExternally()` or `reauthenticateExternally()` changes its parameters;
- link eligibility stops being answered from the application's memberships (`provisioning-and-tenancy.md`), which
  changes what a link does, or the tenant authentication policy (`tenant-authentication-policy.md`) changes what an
  enforcement change revokes;
- `laravel-sso` changes what its `Identities\Caller` carries or which of its calls take one (`Callers` names it), or
  asks freshness after the guards in its lock order (the adapter can then judge current under the session's row lock),
  `laravel-mfa`'s proofs carry a provider's methods (a rebound combination policy can then trust them),
  `laravel-authentication` gains a lookup by verified identifier or names a connection's tenant to the evidence policy,
  or SSO's `AuthenticationContext` keys or stored form change;
- FEATURES allows a session through a link of no verified domain provenance to confirm a link (link confirmation may
  then admit one by its `sso.link_provenance`), `laravel-authentication` changes what its `recovery` channel admits, or
  changes what its proof or provenance reader locks or answers for;
- the rate-limit counters move off the storage connection by default, which changes what an authentication refusal
  rolls back;
- Laravel runs a transaction's remaining commit callbacks, or fires `TransactionCommitted`, when one of them fails
  (the second pass's release at the end of the unit of work may then go), or Octane gives its events dispatcher each
  request's sandbox (the commit listeners may then be resolved by the dispatcher again).
