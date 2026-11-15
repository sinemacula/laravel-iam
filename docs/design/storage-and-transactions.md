# Storage and Transactions

The tables of `laravel-authentication`, `laravel-authorization`, `laravel-mfa` and `laravel-sso` live on one
connection, so a change that spans members commits as one.

## Storage connection

- `iam.storage.connection` is written into each of those members' unset connection keys (`authorization.connection`
  for `laravel-authorization`). A key naming another connection refuses boot with `StorageConnectionMismatchException`.
- `laravel-audit-log` may keep its own connection; `iam:check` notes that its refusal of a read of the trail inside a
  change does not cover it.
- SSO's attempt counters belong on `sso.rate_limits.connection`, off the storage connection, so a redemption rolled
  back still counts its attempt. While SSO is in use and its own limiter is bound, `iam:check` notes counters on the
  storage connection.
- The keys are aligned at registration, again once every provider has registered, and checked once more after boot,
  since a provider's `boot()` can still register a member or change a key.
- The check is skipped while a configuration command or `iam:check` runs, so a bad value can still be inspected and
  cleared.
- `iam:check` also checks that the guards' identity models are on that connection.

## Cross-member transactions

`Iam::transaction()` runs the work through Laravel's `transaction($work, $attempts)` on the storage connection.

- Only the outermost transaction retries, up to `iam.transactions.attempts`. Inside the caller's own transaction the
  failure is rethrown for the caller to retry.
- A concurrency failure anywhere in the exception chain is rethrown as a `DeadlockException` with SQLSTATE 40001, since
  a nested transaction drops PostgreSQL's string SQLSTATE.
- A failure from an after-commit callback is never retried.
- Flows whose transaction a member opens itself (MFA's verifications and factor changes, SSO's standalone `link`) are
  not wrapped; the caller retries the request.

## After commit

Laravel's `afterCommit()` waits on whichever connection opened a transaction last. Work that must wait on the storage
connection's commit goes through laravel-mfa's `AfterStorageCommit::run()`. `ConnectionTransactions::open()` lists one
connection's open transactions.
