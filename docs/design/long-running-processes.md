# Long-Running Processes

Nothing one request or job bound may reach the next in an Octane worker, a queue worker or another long-lived process.

## Decisions

- The `iam` manager resolves every service from the current container on each call, so it reaches each Octane
  request's sandbox.
- `WorkerReset::reset()` (`Iam::resetWorkerState()`) flushes the suite's request state through each member's own reset
  where it has one:
  - the resolved session, which holds laravel-mfa's default proof store, and `AuthManager::forgetGuardState()`;
  - laravel-sso's and laravel-authorization's `RequestState::forget()`;
  - every binding under `iam.scoped:`, the package's own scoped adapters and records;
  - the facade roots, which live outside the container.
- Every other scoped instance is kept: Laravel's `Context` and `defer()` callbacks, and audit-log's execution frames.
- `ResetWhenWorkerStarts` runs `reset()` as each Octane worker starts, so nothing from boot is cloned into the first
  request.
- `ResetBetweenRequests` runs `forgetMemberState()` before each Octane request. Octane forgets scoped instances itself.
- `ResetBeforeJob` flushes the session before each non-`sync` queued job. laravel-authentication resets its guards and
  the queue worker forgets scoped instances.
- The Octane listeners are registered by event name, so Octane stays optional. All three are on while
  `iam.workers.reset` is; only a clear off value (`false`, `0`, `off`, `no`) turns it off.

## Invariants

- An adapter holding request state is scoped, never a singleton.
- A `sync` job keeps its dispatcher's guards and session.
- Any other long-lived process calls `Iam::resetWorkerState()` between units of work.

## Member gaps

- `laravel-authentication`: no public reset for its scoped request state, so `WorkerReset::AUTHENTICATION_STATE` lists
  `Rehashing`, `KeptSessions`, `RequiredWork` and `WatchedSessions`.
- `laravel-mfa`: no reset of its session-held proofs before a job, so `ResetBeforeJob` flushes the session.
