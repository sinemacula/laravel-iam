# Long-Running Processes

## Purpose

This note describes how nothing one request or job bound reaches the next in a long-lived process (IAM-1.4, IAM-11.3):
what the combined worker reset flushes, when it runs under Octane and the queue worker, and how another long-lived
process calls it.

## Invariants

- Before `reset()` (or `Iam::resetWorkerState()`) forgets anything, it releases the work this package held for a
  commit that finished without running it, a commit callback having failed
  (`Transactions\AfterConnectionCommits::settle()`, a policy change's second pass among it), on every connection with
  no transaction open, reporting what it throws; the request's or the command's termination and a queued job's end
  release it the same way (`sso-redemption-and-revocation.md`).
- The `iam` manager, and this package's commit listeners, resolve every service and record from the application
  current when they run, never from a container kept since, so a manager resolved in the worker's application before
  Octane clones it, and the events dispatcher Octane keeps on the worker's application, still reach each request's
  sandbox and its scoped records.
- One reset flushes every member's request state, `Workers\WorkerReset::reset()` (or `Iam::resetWorkerState()`), in
  two halves:
  - `forgetMemberState()` resets every `laravel-authentication` guard already resolved to the current request, through
    its `AuthManager::forgetGuardState()`, creating none. The auth manager is never built for it: when nothing has
    resolved `auth`, no guard can hold state. A manager bound to `auth` that is not the package's is left alone. When
    the container being reset is an application, the manager is pointed at it first (`setApplication()`), as Octane's
    `FlushAuthenticationState` points it at each request's sandbox: the manager is shared across a worker's requests
    and resolves the request from the application it holds, which, until Octane's listener has run for the request,
    is the last request's sandbox, already flushed, so `make('request')` would fail on every request after the first.
  - `forgetMemberState()` also drops the callers `laravel-authentication` keeps on the current request's attributes,
    under `authentication.caller.` followed by the credential, the guard and the action (`CallerCredentials`), building
    no request and leaving a `request` binding that is not a request, and every other attribute, alone.
    `Auth::caller()` is read once per request and kept there, and every job a worker runs shares one request, so without
    it every later job would be decided about the first job's caller, its grants, tenant and session, whoever its guards
    held (`Authorization\SubjectResolverAdapter::resolve()`, `authorization.md`). `laravel-authentication`'s own
    `ForgetGuardStateBeforeJob` resets the guards but leaves the memo, a gap in that member.
  - `forgetMemberState()` also flushes the session already resolved (`session.store`), building none, and leaves a
    `session.store` binding that is not an `Illuminate\Contracts\Session\Session` alone, as it leaves another `auth`
    manager: such a binding holds none of the proofs below, and calling `flush()` on it could fail inside every job's
    and every request's listener. `laravel-mfa`'s default proof store (`Proofs\SessionProofStore`) keeps its proof
    records in the Laravel session, and a worker's session lives in memory for as long as the worker does, outside
    Laravel's scoped instances, so without it a job would read the proofs an earlier job made for the same person and
    pass a step-up or requirement check it never made; `laravel-mfa`'s own operations guide asks for the same flush
    before each job that is not `sync`. It runs only between units of work, before the next one starts a session of its
    own.
  - The members' scoped request state is forgotten: the scoped bindings `laravel-authentication` (`Rehashing`, and the
    `KeptSessions`, `RequiredWork` and `WatchedSessions` that hold a unit of work's kept sessions, the work due at its
    commit, such as a sign-in's admission recheck, and the sessions checked at that commit), `laravel-sso` (its scoped
    stores, resolvers and fetcher, and the `DriverScope` that tells its protocol manager a scope has ended) and
    `laravel-authorization` keep request state in, listed in `WorkerReset::SCOPED_STATE`. Authorization is installed
    and active from M1, binding its request state with `scoped()`: its `ResolvedTenant` holder, `ResolutionCache`,
    `LastDecisionStore`, `PolicyEvaluator`, `SessionScopes`, `CheckContextFactory`, the `DeclaredAbilities` its Gate
    hook answers, the `SchemaInspector` that reads, once a request or job, the tables and connections its
    `whereAuthorized()` query scope reads, the `Previewing` that holds whether a preview is being evaluated and the
    subjects its previews are about, and its `authorization` manager, and
    every default behind its contracts (its subject resolver, policy store and policy resolver, its tenant tree, its
    check contexts among them) under its own `authorization.default:` keys, which `WorkerReset::isSuiteState()` finds
    by that prefix, so a default authorization adds is forgotten with the rest (the contracts themselves resolve
    through those keys with a plain `bind()`, so an application's own binding of a contract is never scoped, and is
    kept). `laravel-audit-log`'s scoped execution frames, request identity and capture state are left out on purpose,
    as below. `tests/Feature/Workers/WorkerResetTest.php` compares the reset against every scoped binding the
    installed members make, so a member's next scoped binding cannot be missed.
    Forgetting them needs no authorization API; without it a long-running command that resets between tenants would
    keep the first tenant's `ResolvedTenant`, decision and resolutions, and an
    Octane worker would clone what its boot resolved into its first request. This package's scoped adapters are never
    listed there: the binding rule scopes each under its own key, `BindingRule::SCOPED_PREFIX` (`iam.scoped:`) followed
    by the seam, and takes the seam itself off the container's scoped list (see `binding-precedence.md`), so
    `WorkerReset::isSuiteState()` finds them by that prefix and the list never changes for them; listing the seam in
    `SCOPED_STATE` would do nothing. Each is forgotten with `forgetInstance()`, so the next unit of work builds its own,
    but only while the container still keeps it as scoped, as Laravel's own `forgetScopedInstances()` does. An instance
    or a singleton the application bound over one of those seams before the member registered, which the member's
    `scopedIf()` then left alone (IAM-8.4), is the application's: forgetting an instance would leave the seam
    unresolvable in every sandbox cloned from the worker, and forgetting a singleton would rebuild it. The container
    lists its scoped abstracts only in its protected `scopedInstances`, which the reset reads through a closure bound to
    the container's class, as `MemberDefaults` reads the binding table. That list also holds the closure itself for a
    binding scoped by its closure's return type (`scoped(fn (): Foo => ...)`), which any provider can make; every
    abstract the suite keeps request state under is a string, so such an entry is passed over and kept, never handed to
    `isSuiteState()`, which would refuse it.
  - Once the scoped state is forgotten, the roots Laravel's facades keep are cleared (`Facade::clearResolvedInstances()`),
    as the queue worker clears them straight after its own `forgetScopedInstances()` and Octane as it switches
    application. A facade keeps the root it first resolved in a static cache outside the container, which
    `forgetInstance()` leaves holding it: `laravel-authorization`'s `Authorization` facade resolves the scoped
    `authorization` manager and keeps it, and the manager holds its `LastDecisionStore`, `PolicyEvaluator` and
    resolvers in readonly properties, so without the clear a command that resets between tenants would keep the first
    tenant's last decision, evaluator, resolvers and resolution memo through the facade, authorization's main API,
    while the container had forgotten them. Every root is cleared, not only those under the keys forgotten: a facade may
    name a member's state by an alias (`AuthorizationManager` for `authorization`), or be a real-time facade, and a
    cleared root resolves again from the container, so a facade over anything the reset kept (`Context` among them)
    returns the same instance it did. Only `reset()` clears them; the Octane request and queue job listeners call
    `forgetMemberState()` alone, and Octane and the queue worker clear the roots themselves. The provider calls
    `forgetScopedState()` once more as the application finishes booting, when it binds the adapters again over the
    defaults of a `laravel-authorization` registered from another provider's `boot()` (`authorization.md`), so nothing
    resolved from those defaults while the application booted outlives them.
  - Every other scoped instance is kept, never flushed with `forgetScopedInstances()`: Laravel keeps a command's or a
    job's `Context` and its `defer()` callbacks in scoped instances, and `laravel-audit-log` its execution frames, its
    commit queue and its captured events, which it enters, flushes and leaves itself as each request, command and job
    starts and ends. A reset called by hand between the units of work of a command would otherwise drop the deferred
    callbacks before they ran, the command's `Context` and the audit trail's command frame. Laravel's own workers
    forget every scoped instance only at their own boundaries, once a job's deferred callbacks have run.
  - `Mfa\FactorCodeCallers`, which this package binds outside the binding rule (it is no member's seam), is scoped
    under the same `iam.scoped:` prefix and resolved through it, so the reset forgets it with this package's scoped
    adapters. It keeps the caller MFA handed the challenge gateway only under the factor code binding the gateway made,
    a weak key, so nothing in it outlives the code's send or check; forgetting it on the explicit reset as well means a
    caller kept for a binding something still references is never read back after a reset called between units of
    work.
  - `Audit\JobCallers`, the caller each queued job running carried from whoever dispatched it (`audit-mapping.md`), is
    frame state, as `laravel-audit-log`'s execution frames are, not a unit of work's request state: it is scoped under
    its own class, outside the `iam.scoped:` prefix, so the queue worker and Octane forget it at their own boundaries
    and a job's frames are its own, while a reset called by hand between a job's own units of work keeps the caller
    the job carried, for its later records and the jobs it dispatches, as it keeps audit-log's job frame.
- `laravel-mfa` keeps no container instance of any seam between requests (since laravel-mfa#92 every default is bound
  with `bindIf()` and its `mfa` manager with `singletonIf()`, none of them holding request state), so its bindings need
  no reset; its request state is the session-held proofs above, and the identity the guards resolve.
  `laravel-authorization`'s explicit resets (`LastDecisionStore::reset()`, `ResolutionCache::flush()`,
  `TenantScope::flushResolvedTenant()`) are not called: each clears state held in a scoped instance forgotten above,
  and what it added since (what its previews know, the console subject resolver its explanations resolve through, held
  under an `authorization.default:` key) is scoped too, its explanations keeping nothing beyond the check. Its remaining
  static state (`OperationScope`, held only while an operation runs, and its observers' weak maps) is no request's. The
  adapters this package binds over its seams keep nothing; the subject resolver and application access are scoped all
  the same, under `iam.scoped:`, the resolver because `laravel-authorization` keeps the tenant it resolved for a unit of
  work only while the resolver bound is the one that resolved it (`authorization.md`).
- `Workers\ResetWhenWorkerStarts` runs the whole `reset()` once as each Octane worker starts, on the event's `app`, the
  application every request's sandbox is cloned from, or the current application when the event carries none. It
  listens to `Laravel\Octane\Events\WorkerStarting` by its name, so Octane stays optional and is no dependency.
  Anything the worker's boot left in a member's scoped instance would otherwise be cloned into the first request's
  sandbox.
- `Workers\ResetBetweenRequests` resets before each Octane request, with `forgetMemberState()` only. It listens to
  `Laravel\Octane\Events\RequestReceived` by its name. Octane dispatches the event once the request's sandbox is the
  current application, and the listener resets the event's `sandbox`, or the current application when the event
  carries none:
  - Octane registers its own listeners, the ones in `octane.listeners` among them, as `OctaneServiceProvider` boots,
    so whether they run before or after this one follows the providers' boot order: Octane's provider boots after this
    package's when an application registers it by hand (Octane in `dont-discover`, or discovery off). The reset relies
    on neither order: it points the auth manager at the sandbox itself before resetting its guards, rather than
    relying on Octane's `FlushAuthenticationState` having done so
    (`testEachRequestResetsTheGuardsWhateverSandboxTheAuthManagerLastHeld`).
  - The scoped instances are left alone: every sandbox is a fresh clone of the worker's application, whose scoped
    instances Octane forgets once each operation ends (`FlushTemporaryContainerInstances`) and this package forgets as
    the worker starts, so none is left from the last request. Any listener that runs before this one, Octane's or the
    application's, may already have filled some for the request (Laravel's `Context`, its deferred callbacks), which
    a second flush would discard.
- `Workers\ResetBeforeJob` resets before each queued job, on `JobProcessing`, with `forgetMemberState()` only:
  - A job on the `sync` connection runs inside the request or command that dispatched it, which owns that state, so
    it is skipped, as `laravel-authentication`'s own `ForgetGuardStateBeforeJob` skips it; its guards and its session,
    which flushing would sign out, are that request's.
  - The scoped instances are left alone: the queue worker forgets them itself before it fetches each job, and by the
    time this listener runs, other `JobProcessing` listeners have already filled some for the job (`laravel-audit-log`
    pushes its job frame), which a second flush would discard.
- The three listeners are registered in `IamServiceProvider::boot()` while `iam.workers.reset` (`IAM_WORKERS_RESET`)
  is on, which it is by default; turned off, none is registered. The switch is read leniently, as an environment
  variable fills it: `false` (as a boolean or as text), `0`, `off` and `no` turn it off, and anything else, a missing,
  empty or unrecognised value included, leaves it on. A value is never refused, since refusing it would stop every
  command from booting, the ones that clear a cached configuration among them.

## Success Path

- Under Octane, each worker starts with no member's scoped instance left from its boot, and each request starts with
  every guard reset to it, the session flushed before it starts (as Octane's own `FlushSessionState` flushes it too),
  and no scoped instance left from the last request. Octane's own listeners
  (`FlushAuthenticationState`, and forgetting the temporary container instances once an operation ends) still run;
  the reset adds the package guards' state.
- Under `queue:work`, each job starts with every guard reset, an empty session, and the scoped instances the worker
  forgot before fetching it.
- Any other long-lived process (a custom daemon, a loop in a command) calls `Iam::resetWorkerState()` between units of
  work. Its `defer()` callbacks still run as it finishes, and its `Context`, the audit log's command or job frame and
  the caller a job carried are kept; its in-memory session is flushed, and a facade over a member's scoped state
  (`Authorization::lastDecision()`) reads the next unit's, not the first one's. Calling it in the middle of a web
  request would flush that request's session.

## Failure / Edge Cases

- An adapter that holds request state in a singleton would outlive the reset; that is why such adapters are scoped
  (see `binding-precedence.md`), and the binding rule binds them with that lifetime.
- An object that captured a guard or a scoped instance before the reset keeps its reference; the reset reaches only
  what is resolved from the container, or through a facade, afterwards.
- With `iam.workers.reset` off, the application performs the same reset itself, or state leaks between requests and
  jobs.
- An application that removes `FlushTemporaryContainerInstances` from Octane's `OperationTerminated` listeners keeps
  only what the worker's application resolved itself between requests; a request's own scoped instances live in its
  sandbox, which is discarded.
- A `sync` job's dispatcher keeps its guards: the job acts as the request or command that dispatched it.

## Implementation Anchors

- `src/Workers/WorkerReset.php`: `reset()`, `forgetMemberState()`, `forgetGuardState()`, `forgetCallers()`,
  `flushSession()`, `resolve()`, `forgetScopedState()`, `isSuiteState()`, `scopedAbstracts()`, `SCOPED_STATE`,
  `AUTHORIZATION_DEFAULT`, `CALLER_MEMO`.
- `src/Bindings/BindingRule.php`: `SCOPED_PREFIX`, the prefix `WorkerReset::isSuiteState()` finds this package's
  scoped adapters by, `bindScoped()` and `unscope()`.
- `src/Workers/ResetWhenWorkerStarts.php`: `EVENT`, `__invoke()`; `src/Workers/ResetBetweenRequests.php`: `EVENT`,
  `__invoke()`; `src/Workers/ResetBeforeJob.php`: `__invoke()`.
- `src/IamServiceProvider.php`: `registerListeners()`, `registerFactorCodeCallers()`; `src/Mfa/FactorCodeCallers.php`;
  `src/IamManager.php`: `resetWorkerState()`; `src/Transactions/AfterConnectionCommits.php`: `settle()`;
  `config/iam.php`: `workers`.

## Authoritative Tests

- `tests/Unit/Workers/WorkerResetTest.php` `testResetForgetsTheMembersScopedState`,
  `testResetForgetsThePackagesScopedAdapters`, `testResetForgetsTheMembersScopedStateListedAfterAnotherScopedInstance`,
  `testResetKeepsEveryOtherScopedInstance`, `testResetKeepsAScopedBindingKeyedByItsClosure`,
  `testResetKeepsAnInstanceWithNoScopedBinding`, `testResetClearsTheRootAFacadeResolvedFromAMembersScopedState`,
  `testAFacadeOverAKeptScopedInstanceReturnsTheSameInstance`,
  `testResetKeepsASingletonOverAMembersScopedSeam`, `testResetFlushesTheSession`,
  `testForgettingTheMemberStateFlushesTheSession`, `testAnUnresolvedSessionIsNotBuilt`,
  `testAnotherSessionStoreIsLeftAlone`, `testForgettingTheMemberStateDropsTheRequestsCallers`,
  `testAnUnresolvedOrAnotherRequestIsLeftAlone`
- `tests/Integration/Authorization/SubjectResolverAdapterTest.php` `testEachJobInAWorkerIsDecidedAboutItsOwnCaller`
- `tests/Feature/Workers/WorkerResetTest.php` `testResetForgetsEveryScopedInstanceTheMembersBind` (every scoped
  binding of `laravel-authentication`, `laravel-authorization`, `laravel-mfa`, `laravel-sso` and this package, as the
  installed members make them, but this package's job frames), `testResetKeepsEveryOtherScopedInstance`
  (`laravel-audit-log`'s, this package's `Audit\JobCallers` and Laravel's own),
  `testResetRunsTheWorkACommitLeftHeldFirst`
- `tests/Feature/Audit/CarryCallerIntoJobsTest.php` `testAResetInsideAJobKeepsTheCarriedCaller`,
  `testTheJobCallersAreScopedAndKeptByTheExplicitReset`
- `tests/Feature/IamManagerTest.php` `testEachServiceIsResolvedFromTheCurrentApplication`,
  `testResettingTheWorkerStateForgetsTheAuthorizationRequestState`,
  `testResettingTheWorkerStateForgetsTheDecisionTheAuthorizationFacadeHolds`,
  `testResettingTheWorkerStateByHandKeepsWhatTheCommandHolds`
- `tests/Feature/Workers/ResetWhenWorkerStartsTest.php` `testTheListenerIsRegisteredByTheEventsName`,
  `testTheWorkersStartResetsTheEventsApplication`,
  `testAnInstanceTheApplicationBindsBeforeSsoRegistersOutlivesTheWorkersStart`,
  `testTurningTheResetOffRegistersNoListener`
- `tests/Feature/Workers/ResetBetweenRequestsTest.php` `testTheListenerIsRegisteredByTheEventsName`,
  `testEachRequestResetsTheEventsSandbox`, `testEachRequestResetsTheGuardsWhateverSandboxTheAuthManagerLastHeld`,
  `testAScopedInstanceAnEarlierListenerFilledOutlivesTheReset`,
  `testTurningTheResetOffRegistersNoListener`
- `tests/Feature/Workers/ResetBeforeJobTest.php` `testEachJobResetsTheGuards`, `testASyncJobLeavesTheGuardsAlone`,
  `testEachJobFlushesTheSession`, `testASyncJobKeepsTheSession`, `testTheJobsScopedInstancesAreKept`,
  `testTheAuditLogsJobFrameOutlivesTheReset`
- `tests/Feature/IamServiceProviderTest.php` `testTheWorkerResetListenersAreRegistered`,
  `testTheWorkerResetIsOnWhenTheSwitchIsMissing`, `testTurningTheWorkerResetOffRegistersNeitherListener`,
  `testTheWorkerResetSwitchIsReadAsTheEnvironmentFillsIt`, `testTheFactorCodeCallersAreScoped`,
  `testTheWorkerResetForgetsTheFactorCodeCallers`

## Change Triggers

- An adapter or member that keeps request state outside a scoped binding: it joins `forgetMemberState()`, as
  `laravel-authorization`'s explicit resets would if it ever kept state outside its scoped instances.
- `laravel-mfa`'s session proof store ceasing to be a store an application can run on: this package's own proof store
  (IAM-3.11) keeps nothing in the Laravel session, but MFA's default is still bound wherever `iam.adapters.mfa` is off
  or the application binds it, and the session flush exists for it; it moves out of `forgetMemberState()` only once no
  application can keep it.
- A change to the protected `Container::$scopedInstances` the reset reads, or a public way to ask whether an abstract
  is scoped, which the reset then uses instead.
- A member adding, renaming or removing a scoped binding that keeps request state (`laravel-authorization` changing
  its `authorization.default:` prefix, or moving a binding off `scoped()`, among them): `WorkerReset::SCOPED_STATE`
  and `AUTHORIZATION_DEFAULT` follow, as `tests/Feature/Workers/WorkerResetTest.php` reports.
- A change to `BindingRule::SCOPED_PREFIX` or `bindScoped()`: `WorkerReset::isSuiteState()` follows. This package
  binding a new scoped adapter changes neither.
- Laravel changing what its container lists among its scoped instances (the closure it lists for a binding scoped by
  its closure's return type, among them): `WorkerReset::forgetScopedState()` and `BindingRule::unscope()` follow.
- Octane changing when it registers its listeners, or `FlushAuthenticationState` ceasing to point the auth manager at
  the sandbox.
- A change to the Octane event names, to how Octane sets the sandbox, or to when the queue worker forgets scoped
  instances or clears the facades' roots.
- A member adding a facade over request state it does not keep in a scoped instance: clearing the root then reaches
  nothing the container rebuilds, and that state joins `forgetMemberState()`.
- `laravel-authentication` adding a listener of its own for Octane requests.
