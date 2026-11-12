# Long-Running Processes

## Purpose

This note describes how nothing one request or job bound reaches the next in a long-lived process (IAM-1.4, IAM-11.3):
what the worker reset flushes, when it runs under Octane and the queue worker, and how another long-lived process calls
it.

## Invariants

- The `iam` manager resolves every service and record from the application current when it runs, never from a
  container kept since, so it still reaches each Octane request's sandbox and its scoped records.
- `Workers\WorkerReset::reset()` (or `Iam::resetWorkerState()`) flushes the suite's request state through each member's
  own reset where it has one:
  - `forgetMemberState()` flushes the session already resolved, where `laravel-mfa`'s default proof store
    (`Proofs\SessionProofStore`) keeps its proofs, and calls `laravel-authentication`'s
    `AuthManager::forgetGuardState()`, which resets every resolved guard to the current request and forgets the
    request's callers. Nothing unresolved is built, and an `auth` or `session.store` binding that is not the member's
    manager or a session is left alone. The manager is first pointed at the application being reset, since under
    Octane it may still hold the last request's sandbox.
  - `laravel-sso` and `laravel-authorization` forget their own scoped instances through their
    `Support\RequestState::forget()`.
  - `laravel-authentication` has no public reset for its scoped request state, so `WorkerReset::AUTHENTICATION_STATE`
    lists it (`Rehashing`, `KeptSessions`, `RequiredWork`, `WatchedSessions`).
  - This package's scoped adapters and records are bound under `SeamBinding::SCOPED_PREFIX` (`iam.scoped:`), and every
    binding under that prefix is forgotten.
  - `Facade::clearResolvedInstances()` then clears the facade roots, which a facade keeps outside the container
    (`laravel-authorization`'s `Authorization` facade holds its scoped manager).
  - Every other scoped instance is kept: Laravel's `Context` and `defer()` callbacks, and `laravel-audit-log`'s
    execution frames, which it enters and leaves itself.
- `laravel-mfa` keeps no container instance of any seam between requests, so its only request state is the session.
- `Workers\ResetWhenWorkerStarts` runs `reset()` as each Octane worker starts, on the event's `app`, so nothing the
  worker's boot left is cloned into the first request's sandbox.
- `Workers\ResetBetweenRequests` runs `forgetMemberState()` before each Octane request, on the event's `sandbox`. The
  scoped instances are left alone: Octane forgets them once each operation ends, and earlier listeners may already
  have filled some for this request.
- `Workers\ResetBeforeJob` flushes the session before each queued job that is not `sync`. `laravel-authentication`'s
  own `ForgetGuardStateBeforeJob` resets its guards and callers, and the queue worker forgets the scoped instances
  before it fetches the job.
- Both Octane listeners are registered by the events' names, so Octane is no dependency. The three listeners are
  registered while `iam.workers.reset` (`IAM_WORKERS_RESET`) is on, the default. `false`, `0`, `off` and `no` turn it
  off; any other value, a missing or empty one included, leaves it on.

## Success Path

- Under Octane, each worker starts with no member's scoped instance left from its boot, and each request starts with
  every guard reset to it and the session flushed.
- Under `queue:work`, each job starts with every guard reset, an empty session and fresh scoped instances.
- Any other long-lived process calls `Iam::resetWorkerState()` between units of work, and forgets its own scoped
  bindings with the container's `forgetScopedInstances()`. Calling it in the middle of a web request flushes that
  request's session.

## Failure / Edge Cases

- An adapter that holds request state in a singleton would outlive the reset, so such adapters are scoped (see
  `binding-precedence.md`).
- An object that captured a guard or a scoped instance before the reset keeps its reference.
- With `iam.workers.reset` off, the application performs the same reset itself.
- A `sync` job keeps its dispatcher's guards and session.

## Implementation Anchors

- `src/Workers/WorkerReset.php`: `reset()`, `forgetMemberState()`, `flushSession()`, `AUTHENTICATION_STATE`.
- `src/Workers/ResetWhenWorkerStarts.php`, `src/Workers/ResetBetweenRequests.php`, `src/Workers/ResetBeforeJob.php`.
- `src/IamServiceProvider.php`: `registerListeners()`; `src/IamManager.php`: `resetWorkerState()`;
  `config/iam.php`: `workers`.

## Authoritative Tests

- `tests/Unit/Workers/WorkerResetTest.php`
- `tests/Feature/Workers/WorkerResetTest.php` `testResetForgetsEveryScopedInstanceTheMembersBind`,
  `testResetKeepsEveryOtherScopedInstance`
- `tests/Integration/Authorization/SubjectResolverAdapterTest.php` `testEachJobInAWorkerIsDecidedAboutItsOwnCaller`
- `tests/Feature/Workers/ResetWhenWorkerStartsTest.php`, `tests/Feature/Workers/ResetBetweenRequestsTest.php`,
  `tests/Feature/Workers/ResetBeforeJobTest.php`
- `tests/Feature/IamServiceProviderTest.php` `testTheWorkerResetListenersAreRegistered`,
  `testTheWorkerResetSwitchIsReadAsTheEnvironmentFillsIt`, `testTheWorkerResetForgetsTheFactorCodeCallers`

## Change Triggers

- `laravel-authentication` publishing a reset for its scoped state: `AUTHENTICATION_STATE` goes.
- `laravel-mfa` forgetting its session-held proofs before each job itself: `ResetBeforeJob` goes.
- A member adding request state outside its scoped instances, or changing its `RequestState::forget()`.
- A change to the Octane event names or to when Octane and the queue worker forget scoped instances.
