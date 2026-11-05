# Long-Running Processes

## Purpose

This note describes how nothing one request or job bound reaches the next in a long-lived process (IAM-1.4, IAM-11.3):
what the combined worker reset flushes, when it runs under Octane and the queue worker, and how another long-lived
process calls it.

## Invariants

- One reset flushes every member's request state, `Workers\WorkerReset::reset()` (or `Iam::resetWorkerState()`), in
  two halves:
  - `forgetMemberState()` resets every `laravel-authentication` guard already resolved to the current request, through
    its `AuthManager::forgetGuardState()`, creating none. The auth manager is never built for it: when nothing has
    resolved `auth`, no guard can hold state. A manager bound to `auth` that is not the package's is left alone.
  - The members' scoped request state is forgotten: the scoped seams `laravel-authentication` (`Rehashing`) and
    `laravel-sso` (its scoped stores, resolvers and fetcher, and the `DriverScope` that tells its protocol manager a
    scope has ended) keep request state in, listed in `WorkerReset::SCOPED_STATE`; `laravel-authorization`'s and this
    package's scoped adapters join the list with their milestones. Each is forgotten with `forgetInstance()`, so the
    next unit of work builds its own.
  - Every other scoped instance is kept, never flushed with `forgetScopedInstances()`: Laravel keeps a command's or a
    job's `Context` and its `defer()` callbacks in scoped instances, and `laravel-audit-log` its execution frames, its
    commit queue and its captured events, which it enters, flushes and leaves itself as each request, command and job
    starts and ends. A reset called by hand between the units of work of a command would otherwise drop the deferred
    callbacks before they ran, the command's `Context` and the audit trail's command frame. Laravel's own workers
    forget every scoped instance only at their own boundaries, once a job's deferred callbacks have run.
- `laravel-mfa` keeps no instance of any seam between requests (every binding but its `mfa` manager is transient), so
  it needs no reset of its own. `laravel-authorization`'s request tier and last decision join the reset in M11.
- `Workers\ResetWhenWorkerStarts` runs the whole `reset()` once as each Octane worker starts, on the event's `app`, the
  application every request's sandbox is cloned from, or the current application when the event carries none. It
  listens to `Laravel\Octane\Events\WorkerStarting` by its name, so Octane stays optional and is no dependency.
  Anything the worker's boot left in a member's scoped instance would otherwise be cloned into the first request's
  sandbox.
- `Workers\ResetBetweenRequests` resets before each Octane request, with `forgetMemberState()` only. It listens to
  `Laravel\Octane\Events\RequestReceived` by its name. Octane dispatches the event once the request's sandbox is the
  current application, and the listener resets the event's `sandbox`, or the current application when the event
  carries none:
  - The scoped instances are left alone: every sandbox is a fresh clone of the worker's application, whose scoped
    instances Octane forgets once each operation ends (`FlushTemporaryContainerInstances`) and this package forgets as
    the worker starts, so none is left from the last request. Octane's own listeners, and the application's in
    `octane.listeners`, run before this one and may already have filled some for the request (Laravel's `Context`, its
    deferred callbacks), which a second flush would discard.
- `Workers\ResetBeforeJob` resets before each queued job, on `JobProcessing`, with `forgetMemberState()` only:
  - A job on the `sync` connection runs inside the request or command that dispatched it, which owns that state, so
    it is skipped, as `laravel-authentication`'s own `ForgetGuardStateBeforeJob` skips it.
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
  every guard reset to it and no scoped instance left from the last request. Octane's own listeners
  (`FlushAuthenticationState`, and forgetting the temporary container instances once an operation ends) still run;
  the reset adds the package guards' state.
- Under `queue:work`, each job starts with every guard reset, and with the scoped instances the worker forgot before
  fetching it.
- Any other long-lived process (a custom daemon, a loop in a command) calls `Iam::resetWorkerState()` between units of
  work. Its `defer()` callbacks still run as it finishes, and its `Context` and the audit log's command frame are kept.

## Failure / Edge Cases

- An adapter that holds request state in a singleton would outlive the reset; that is why such adapters are scoped
  (see `binding-precedence.md`), and the binding rule binds them with that lifetime.
- An object that captured a guard or a scoped instance before the reset keeps its reference; the reset reaches only
  what is resolved from the container afterwards.
- With `iam.workers.reset` off, the application performs the same reset itself, or state leaks between requests and
  jobs.
- An application that removes `FlushTemporaryContainerInstances` from Octane's `OperationTerminated` listeners keeps
  only what the worker's application resolved itself between requests; a request's own scoped instances live in its
  sandbox, which is discarded.
- A `sync` job's dispatcher keeps its guards: the job acts as the request or command that dispatched it.

## Implementation Anchors

- `src/Workers/WorkerReset.php`: `reset()`, `forgetMemberState()`, `SCOPED_STATE`.
- `src/Workers/ResetWhenWorkerStarts.php`: `EVENT`, `__invoke()`; `src/Workers/ResetBetweenRequests.php`: `EVENT`,
  `__invoke()`; `src/Workers/ResetBeforeJob.php`: `__invoke()`.
- `src/IamServiceProvider.php`: `registerListeners()`; `src/IamManager.php`: `resetWorkerState()`;
  `config/iam.php`: `workers`.

## Authoritative Tests

- `tests/Unit/Workers/WorkerResetTest.php` `testResetForgetsTheMembersScopedState`,
  `testResetKeepsEveryOtherScopedInstance`
- `tests/Feature/IamManagerTest.php` `testResettingTheWorkerStateByHandKeepsWhatTheCommandHolds`
- `tests/Feature/Workers/ResetWhenWorkerStartsTest.php` `testTheListenerIsRegisteredByTheEventsName`,
  `testTheWorkersStartResetsTheEventsApplication`, `testTurningTheResetOffRegistersNoListener`
- `tests/Feature/Workers/ResetBetweenRequestsTest.php` `testTheListenerIsRegisteredByTheEventsName`,
  `testEachRequestResetsTheEventsSandbox`, `testAScopedInstanceAnEarlierListenerFilledOutlivesTheReset`,
  `testTurningTheResetOffRegistersNoListener`
- `tests/Feature/Workers/ResetBeforeJobTest.php` `testEachJobResetsTheGuards`, `testASyncJobLeavesTheGuardsAlone`,
  `testTheJobsScopedInstancesAreKept`, `testTheAuditLogsJobFrameOutlivesTheReset`
- `tests/Feature/IamServiceProviderTest.php` `testTheWorkerResetListenersAreRegistered`,
  `testTheWorkerResetIsOnWhenTheSwitchIsMissing`, `testTurningTheWorkerResetOffRegistersNeitherListener`,
  `testTheWorkerResetSwitchIsReadAsTheEnvironmentFillsIt`

## Change Triggers

- An adapter or member that keeps request state outside a scoped binding: it joins `forgetMemberState()`, as
  `laravel-authorization`'s will in M11.
- A member adding, renaming or removing a scoped seam that keeps request state, or this package binding a scoped
  adapter: `WorkerReset::SCOPED_STATE` follows.
- A change to the Octane event names, to how Octane sets the sandbox, or to when the queue worker forgets scoped
  instances.
- `laravel-authentication` adding a listener of its own for Octane requests.
