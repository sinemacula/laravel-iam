# Long-Running Processes

Nothing one request or job bound may reach the next in an Octane worker, a queue worker or another long-lived process.

## Decisions

- The `iam` manager resolves every service from the current container on each call, so it reaches each Octane
  request's sandbox.
- `WorkerReset::reset()` (`Iam::resetWorkerState()`) flushes the resolved session, which holds laravel-mfa's default
  proof store, calls `AuthManager::forgetGuardState()`, forgets every scoped instance with the container's
  `forgetScopedInstances()`, and clears the facade roots, which live outside the container.
- `ResetWhenWorkerStarts` runs `reset()` as each Octane worker starts, so nothing from boot is cloned into the first
  request.
- Each Octane request relies on Octane's default listeners to flush the session and the guards.
- `ResetBeforeJob` flushes the session before each non-`sync` queued job. laravel-authentication resets its guards and
  the queue worker forgets scoped instances.
- The Octane listener is registered by event name, so Octane stays optional. Both listeners are on while
  `iam.workers.reset` is; only a clear off value (`false`, `0`, `off`, `no`) turns it off.

## Invariants

- An adapter holding request state is scoped, never a singleton.
- A `sync` job keeps its dispatcher's guards and session.
- Any other long-lived process calls `Iam::resetWorkerState()` between units of work.

## Member gaps

- `laravel-mfa`: no reset of its session-held proofs before a job, so `ResetBeforeJob` flushes the session.
