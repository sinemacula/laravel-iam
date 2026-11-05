# Storage and Transactions

## Purpose

This note describes how every member is kept on the one storage connection the package configures (IAM-2.3), why a
change that spans members runs in one transaction on it (IAM-11.1), and when the package retries that transaction as a
whole after a concurrency failure and when it rethrows instead (IAM-11.2).

## Invariants

- One resolver reads the shared connection, `Storage\StorageConnection`: `name()` is `iam.storage.connection`, read on
  every call, `null` or empty for the default connection; any other value that is not a name fails closed with an
  `InvalidArgumentException` naming the key, rather than putting a member on a connection that was not meant.
  `StorageConnection::read()` reads a member's key by the same rule.
- The member keys that must name the shared connection are `StorageConnection::MEMBER_KEYS`:
  `authentication.storage.connection`, `mfa.storage.connection` and `sso.storage.connection`.
  `laravel-authorization`'s key joins them with AUTHZ-13.7 (M11).
- `Storage\ConnectionAlignment::align()` writes the shared connection into every member key that is unset (`null` or
  empty), from `IamServiceProvider::register()` and again from the booting callback. Members read their connection
  lazily, so a key aligned before boot is the one every model, migration and transaction of the member uses:
  - Only the leaf key is written. Laravel merges a package's configuration one level deep, so a whole `storage` array
    written before a member registers would replace the member's other storage keys, and their environment values.
  - At `register()`, a member whose service provider has not registered yet is left for the second call, and in the
    booting phase so is a member whose configuration is not merged. Composer discovers this package before
    `laravel-mfa` and `laravel-sso`, so at this package's `register()` they have not merged their configuration, and
    writing their keys then would mask their own environment values (`MFA_STORAGE_CONNECTION`,
    `SSO_STORAGE_CONNECTION`). That holds even when the application has published the member's configuration: a
    published file without the `storage` block would gain one holding only the shared connection, and the member's
    one-level merge would keep it over the member's own. By the booting phase every member has merged.
  - `align()` returns what it wrote, and the provider passes what its `register()` wrote to the second call. A key that
    still holds what this package wrote is this package's, not the application's, so it follows the shared connection
    when an application provider registered later names another one (back to unset when that is unset), rather than
    being refused as a mismatch the application never made.
  - With `iam.storage.connection` unset, nothing is written: every unset member key already means the default.
- `ConnectionAlignment::assertAligned()` runs in the booting callback (or wherever the provider settles; see
  `binding-precedence.md`), after the second alignment and before the binding rule, and refuses boot with
  `Exceptions\StorageConnectionMismatchException` when a member key names another connection. Connections are compared
  by the name they resolve to, `database.default` for one unset, so a member key that names the default connection
  agrees with an unset shared one; no connection is opened. The exception names the key and both connections
  (`[default]` for `null`), and carries them as `key`, `member` and `storage`. It is skipped while one of the console
  commands that list, describe, discover, cache or clear configuration runs (`config:cache`, `config:clear`,
  `config:show`, `help`, `list`, `optimize:clear`, `package:discover`), as `laravel-mfa` skips its own boot check for
  them, so a mismatch, a cached one included, can still be inspected and cleared, and Composer's `package:discover`
  still runs; the keys are still aligned and the binding rule still applied. While one of those commands runs, a
  shared or member key that is not a name is left as it is too, and nothing more is aligned
  (`IamServiceProvider::alignStorage()`), so a malformed value baked into a cached configuration can still be cleared.
- A change that spans members runs through `Transactions\CrossMemberTransaction::run()` (or `Iam::transaction()`), in
  one transaction on the storage connection; each member's own transaction inside it is a savepoint, so the members'
  work commits or rolls back as one. Two connections could not commit as one, hence the alignment.
- The retry belongs to whoever opened the outermost transaction, since nothing can be retried from inside a
  savepoint:
  - With no transaction open on the storage connection, `run()` opens it and, after a concurrency failure, runs the
    whole closure again in a new transaction, up to the attempts given or `iam.transactions.attempts`
    (`Transactions\RetrySettings`: 3 when unset; a whole number of at least 1, the first run included, or an
    `InvalidArgumentException`). The last failure, or any failure that is not a concurrency failure, is rethrown.
  - Inside a transaction already open on the storage connection, the closure runs once, in a savepoint inside it, and
    every failure is rethrown for the transaction's owner to retry. A transaction open on another connection does not
    count.
  - A failure rethrown to that owner is handed on in a form its retry recognises
    (`Transactions\ConcurrencyFailures::forCaller()`). Laravel rethrows a concurrency failure met in a savepoint as a
    `DeadlockException` that keeps the message but loses the SQLSTATE, and PostgreSQL's serialisation failure says
    nothing Laravel's detector matches without it; so a `DeadlockException` the detector cannot recognise gives way to
    the first exception in its chain it does recognise (the query's own, with SQLSTATE 40001). A caller's
    `DB::transaction($work, $attempts)` one level out then retries it, as it would with no `run()` in between; a level
    deeper wraps it again exactly as Laravel would. Everything else is rethrown as it is.
- `Transactions\ConcurrencyFailures::isRetryable()` walks the exception and every previous exception. A link is a
  concurrency failure when Laravel's bound `ConcurrencyErrorDetector` says so (SQLSTATE 40001, a MySQL deadlock or lock
  wait timeout, a PostgreSQL deadlock by its message, and the other texts Laravel lists), or when it is SSO's
  `LinkCandidatesChanged`. The walk matters: inside a nested transaction Laravel rethrows a deadlock as a
  `DeadlockException` whose own code is lost, so only its previous exception is detected.
- `run()` does not use the attempts of Laravel's own `transaction()`, which neither walks the chain nor knows SSO's
  exception, nor `transaction()` itself for the attempts it opens: on a failed commit, `transaction()` stops tracking
  the transaction without rolling back the PDO's (SQLite's stays open after a commit refused by a lock), and on
  Laravel 12 it also leaves the attempt's after-commit callbacks queued, to run on the connection's next commit, for
  work that was rolled back. Each attempt is begun with `beginTransaction()` and ended with `commit()`; after any
  failure, of the work or of the commit, `rollBack(0)` rolls the connection back to no transaction at all, the PDO's
  transaction, any transaction the work left open and the attempt's after-commit callbacks with it, on every supported
  Laravel version, before the next attempt and before rethrowing. A rollback that fails too, as on a lost connection,
  leaves the work's own failure as the one rethrown, and the work is not run again.
- A failure once the attempt has committed is rethrown and never retried. Laravel's `commit()` lowers the transaction
  level only once the database has committed, and then runs the after-commit callbacks and the `committed` listeners
  in the same call, so a failure met with no transaction left open is one of theirs, even one the detector recognises
  (a lock wait timeout from a job dispatched to a database queue after the commit): running the work again would apply
  its committed change twice. Laravel's own `transaction()` leaves the same failures unretried. A failure before the
  database commits, from a `committing` listener or the commit itself, is rolled back and retried as above.

## Success Path

- Set `iam.storage.connection` (`IAM_STORAGE_CONNECTION`) once, leave the member keys unset, and run every member's
  migrations: each member's tables, models and transactions are on that connection.
- With both unset, every member is on the default connection and nothing is written.
- A use case that spans members wraps its work in `Iam::transaction(fn () => ...)`; a serialisation failure or deadlock
  on the first attempt is retried as a whole, and its return value comes back.
- Called inside the application's own transaction, the same use case joins it, and a concurrency failure reaches the
  application's outermost transaction, which retries (or rethrows) the whole of it: `Iam::transaction()` retries on
  any link of the chain, and a `DB::transaction($work, $attempts)` one level out retries on the failure as the query
  threw it.
- `DB::afterCommit()` callbacks, and the after-commit records and jobs the members queue, run once, for the attempt
  that committed.

## Failure / Edge Cases

- A member key naming another connection, or naming one while the shared key is unset and the default is another,
  refuses boot naming the key. Unset the member key, or set it to the same connection.
- A malformed shared or member key (not a string) fails closed when it is read, at `register()` or in the booting
  phase, except while a configuration maintenance command runs.
- A mismatch while a configuration maintenance command runs does not refuse boot; the next other command, request or
  job refuses it.
- The whole closure runs again on a retry: its database work is rolled back, but anything else it did (a dispatched
  job, a request to a provider, a mutated object) is repeated. Keep the closure to database work, and dispatch what
  must happen once after the commit.
- Flows whose transaction a member opens itself (MFA's factor changes) cannot be wrapped; the adapters called inside
  them never retry, and the guide says the caller retries the request.
- SSO's starts and completions talk to the provider and refuse to run inside a transaction; only its redemption runs
  through `run()`.
- The identity and principal models must live on the storage connection too (IAM-2.3), but resolving them at boot would
  read the database, so that check is `iam:check`'s (M8).
- Changing the connection moves no table: moving the tables is a deploy, with a migration the application performs and
  a restart of every worker.

## Implementation Anchors

- `src/Storage/StorageConnection.php`: `name()`, `read()`, `MEMBER_KEYS`.
- `src/Storage/ConnectionAlignment.php`: `align()`, `assertAligned()`;
  `src/Exceptions/StorageConnectionMismatchException.php`: `forKey()`.
- `src/IamServiceProvider.php`: `register()`, `settle()`, `alignStorage()`, `isRunningUncheckedCommand()`;
  `config/iam.php`: `storage`, `transactions`.
- `src/Transactions/CrossMemberTransaction.php`: `run()`, `runInside()`, `isCommitted()`, `rolledBack()`;
  `src/Transactions/ConcurrencyFailures.php`: `isRetryable()`, `forCaller()`;
  `src/Transactions/RetrySettings.php`: `attempts()`; `src/IamManager.php`: `transaction()`.

## Authoritative Tests

- `tests/Unit/Storage/StorageConnectionTest.php`
- `tests/Feature/Storage/ConnectionAlignmentTest.php`
  `testUnsetMemberKeysReceiveTheSharedConnectionInAnyOrder`, `testAlignLeavesAMemberWhoseConfigurationIsNotMerged`,
  `testAlignLeavesAMemberWhoseProviderHasNotRegistered`, `testAKeyAnEarlierCallWroteFollowsTheSharedConnection`,
  `testAPublishedConfigurationWithoutStorageKeepsTheMembersOwnConnection`,
  `testAMemberKeyNamingAnotherConnectionRefusesBoot`, `testWithNoSharedConnectionAMemberKeyOffTheDefaultRefusesBoot`
- `tests/Feature/IamServiceProviderTest.php` `testAKeyThisPackageWroteFollowsASharedConnectionChangedLater`,
  `testAMismatchIsNotRefusedWhileAConfigurationCommandRuns`, `testAMismatchIsRefusedOutsideTheConsole`,
  `testAConnectionKeyThatIsNotANameIsNotRefusedWhileAConfigurationCommandRuns`,
  `testAConnectionKeyThatIsNotANameRefusesBootWhileAnotherCommandRuns`
- `tests/Unit/Exceptions/StorageConnectionMismatchExceptionTest.php`
- `tests/Unit/Transactions/ConcurrencyFailuresTest.php`, `tests/Unit/Transactions/RetrySettingsTest.php`
- `tests/Integration/Transactions/CrossMemberTransactionTest.php` (through
  `tests/Concerns/RunsAtIsolationLevels.php`) `testARealSerialisationFailureIsRetriedFromTheOutermostTransaction`
  (PostgreSQL at REPEATABLE READ), `testARealDeadlockIsRetriedFromTheOutermostTransaction` (MySQL and PostgreSQL at
  READ COMMITTED and REPEATABLE READ),
  `testARealSerialisationFailureInsideACallersRetryingTransactionIsRetriedByTheCaller` (PostgreSQL at REPEATABLE READ),
  `testACommitThatFailsOnALockIsRolledBackAndRetried`,
  `testACommitThatFailsOnItsLastAttemptIsRolledBackBeforeItIsRethrown`,
  `testTheAfterCommitCallbacksOfAnAttemptWhoseCommitFailedAreDiscarded`,
  `testTheAfterCommitCallbacksOfACommitThatFailedOnItsLastAttemptNeverRun`,
  `testAFailureOnceTheAttemptHasCommittedIsRethrownWithoutRunningTheWorkAgain`,
  `testAFailureBeforeTheDatabaseCommitsIsRolledBackAndRetried`, `testWhatTheWorkLeftOpenIsRolledBackWithIt`,
  `testARollbackThatFailsLeavesTheWorksFailureRethrownWithoutARetry`,
  `testInsideACallersTransactionTheWorkRunsOnceAndItsFailureIsRethrown`,
  `testInsideACallersTransactionADeadlockIsThrownOnAsLaravelWrapsIt`,
  `testInsideACallersTransactionAFailureLaravelCannotRecogniseWrappedIsThrownOnUnwrapped`,
  `testInsideACallersRetryingTransactionASerialisationFailureIsRetriedByTheCaller`
- `tests/Performance/Transactions/CrossMemberTransactionQueryBudgetTest.php`: one transaction or savepoint per
  attempt, counted by what became of it, and no query of the package's own.

## Change Triggers

- A member adding a storage key, or `laravel-authorization` shipping AUTHZ-13.7: its key joins `MEMBER_KEYS`.
- Any change to how connections are compared, to when the keys are written, or to Laravel's configuration merge.
- A new failure a cross-member transaction should be retried after, or a change to Laravel's concurrency detector or to
  how it wraps a failure inside a nested transaction.
- Any use case that writes two members' tables outside `CrossMemberTransaction`.
