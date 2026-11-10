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
  `authentication.storage.connection`, `mfa.storage.connection`, `sso.storage.connection` and
  `laravel-authorization`'s `authorization.connection`, which it reads on every query, migration and transaction of its
  own, so its grants commit or roll back with a change that spans members (`authorization.md`).
- `Storage\ConnectionAlignment::align()` writes the shared connection into every member key that is unset (`null` or
  empty), from `IamServiceProvider::register()`, again from the booting callback, and once more from a `booted()`
  callback when the application has booted; both callbacks exist for this and the checks below alone (the seam
  bindings are applied in `register()`; see `binding-precedence.md`). Members read their connection lazily, so a key
  aligned before it is first used is the one every model, migration and transaction of the member uses:
  - Only the leaf key is written. Laravel merges a package's configuration one level deep, so a whole `storage` array
    written before a member registers would replace the member's other storage keys, and their environment values.
  - At every call, a member whose service provider has not registered yet, or whose configuration is not merged, is
    left for a later one. Composer discovers this package before
    `laravel-mfa` and `laravel-sso`, so at this package's `register()` they have not merged their configuration, and
    writing their keys then would mask their own environment values (`MFA_STORAGE_CONNECTION`,
    `SSO_STORAGE_CONNECTION`). That holds even when the application has published the member's configuration: a
    published file without the `storage` block would gain one holding only the shared connection, and the member's
    one-level merge would keep it over the member's own. By the booting phase every member registered with the other
    providers has merged; one a provider registers from its own `boot()` merges only then, and is aligned by the
    `booted()` callback.
  - `align()` returns what it wrote, and the provider passes everything it has written to each later call. A key that
    still holds what this package wrote is this package's, not the application's, so it follows the shared connection
    when an application provider registered later, or any `boot()`, names another one (back to unset when that is
    unset), rather than being refused as a mismatch the application never made.
  - With `iam.storage.connection` unset, nothing is written: every unset member key already means the default.
- `ConnectionAlignment::assertAligned()` runs in the booting callback (or from the provider's own `boot()` when it
  registered after the booting callbacks ran; see `binding-precedence.md`) and again in the `booted()` callback, each
  time after the alignment, and refuses boot with `Exceptions\StorageConnectionMismatchException` when the key of a
  member that has registered names another connection. It cannot run in `register()`: a member registered after this
  package has not merged its configuration yet, and an application provider registered later may still name another
  shared connection. It runs again once the application has booted because a `boot()` can register a member, name
  another shared connection or point a member key elsewhere after the booting phase checked; in the `booted()`
  callback, `ConnectionAlignment::assertRegistered()` first refuses a member whose service provider has still not
  registered with `Exceptions\MemberNotRegisteredException`, naming the provider and its key, since that key was never
  aligned and the member, once registered, would read a connection nothing checked (every member is required,
  IAM-1.3). Connections are compared by the name they
  resolve to, `database.default` for one unset, so a member key that names the default connection agrees with an unset
  shared one; no connection is opened. The exception names the key and both connections (`[default]` for `null`), and
  carries them as `key`, `member` and `storage`. It is skipped while one of the console commands that list, describe,
  discover, cache or clear configuration runs (`config:cache`, `config:clear`, `config:show`, `help`, `list`,
  `optimize:clear`, `package:discover`), as `laravel-mfa` skips its own boot check for them, so a mismatch, a cached
  one included, can still be inspected and cleared, and Composer's `package:discover` still runs; the keys are still
  aligned, and the binding rule has already been applied in `register()`. A missing member is not refused then either.
  The command is found as the console finds it (`IamServiceProvider::commandName()`): the first argument that is
  neither an option nor the value of `--env` given after a space, the console's only global option that takes a
  value, and `list`, the console's default, when the arguments name none and the process is Artisan, so `artisan`,
  `artisan -v config:clear` and `artisan --env production config:clear` are all unchecked. Any other process that names
  no command (a test runner given only options, a long-lived worker script that calls `Iam::resetWorkerState()`) runs
  no console command and is checked, as `laravel-mfa`'s own boot check, which reads the first argument, checks it.
  While one of those commands runs, a shared
  or member key that is not a name is left as it is too, and nothing more is aligned
  (`IamServiceProvider::alignStorage()`), so a malformed value baked into a cached configuration can still be cleared.
- A change that spans members runs through `Transactions\CrossMemberTransaction::run()` (or `Iam::transaction()`), in
  one transaction on the storage connection; each member's own transaction inside it is a savepoint, so the members'
  work commits or rolls back as one. Two connections could not commit as one, hence the alignment.
- The retry belongs to whoever opened the outermost transaction, since nothing can be retried from inside a
  savepoint:
  - With no transaction open on the storage connection, `run()` opens it and, after a concurrency failure, runs the
    whole closure again in a new transaction, up to the attempts given or `iam.transactions.attempts`
    (`Transactions\RetrySettings`: 3 when unset; a whole number of at least 1, the first run included, or an
    `InvalidArgumentException`). The last failure, or any failure that is not a concurrency failure, is rethrown as
    the database raised it (`Transactions\ConcurrencyFailures::asRaised()`): a concurrency failure met in a member's
    own nested transaction reaches `run()` as Laravel's `DeadlockException`, which keeps the message but neither the
    SQLSTATE nor the error code, and which Laravel's detector cannot recognise around PostgreSQL's serialisation
    failure; with no transaction left for it to tell, it gives way to the first exception in its chain that is no such
    wrapper and that the detector recognises, the query's own `QueryException` (SQLSTATE 40001, or MySQL's 1213 or
    1205), so a caller that retries the request on a concurrency failure, or asks Laravel's detector, recognises it.
  - Inside a transaction already open on the storage connection, the closure runs once, in a savepoint inside it, and
    every failure is rethrown for the transaction's owner to retry. A transaction open on another connection does not
    count.
  - Whatever the closure wrote is rolled back to that savepoint whenever it fails, so an owner that catches the failure
    and commits keeps none of it (IAM-11.1). Laravel's nested `transaction()` rolls back to the savepoint after any
    failure but a concurrency failure; after one of those it throws a `DeadlockException` (exactly when its detector
    recognises the failure), and before Laravel 13.40 it only lowers the level first. Where the database rolled back
    the failed statement alone (a MySQL lock wait timeout with `innodb_rollback_on_timeout` off, its default; SQLite's
    `database is locked`; MariaDB's changed record), the closure's earlier writes would otherwise stay in the owner's
    transaction. So `runInside()` records the level before it starts and, on a `DeadlockException`, runs the grammar's
    `ROLLBACK TO SAVEPOINT trans<level + 1>` itself, as 13.40 does, on every supported version; where the database has
    already discarded the savepoint (MySQL rolls back the whole transaction after a deadlock), the rollback's failure
    is ignored and the closure's failure is thrown on. Any other failure is left to Laravel's own rollback: a savepoint
    of that name might be an earlier one, when the nested transaction failed to open its own.
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
- A member registered from another provider's `boot()` is aligned and checked once the application has booted, not in
  the booting phase; until then its key is not the shared connection, so nothing should read it from a `boot()`. A
  member registered only once the application has booted, or never, refuses boot when it has: register every member
  with the other providers, as package discovery does.
- The whole closure runs again on a retry: its database work is rolled back, but anything else it did (a dispatched
  job, a request to a provider, a mutated object) is repeated. Keep the closure to database work, and dispatch what
  must happen once after the commit.
- Flows whose transaction a member opens itself (MFA's factor changes) cannot be wrapped; the adapters called inside
  them never retry, and the operations guide says the caller retries the request (`docs/guides/operations.md`,
  Retries).
- SSO's starts and completions talk to the provider and refuse to run inside a transaction; only its redemption runs
  through `run()`.
- The identity and principal models must live on the storage connection too (IAM-2.3), but resolving them at boot would
  read the database, so `iam:check` makes it (`Checks\StorageCheck`): the model of each user provider a `jwt` or
  `api_key` guard uses, read from the model's own connection without a query. No setting names the principal models,
  so the installation guide names them (`docs/guides/installation.md`, The storage connection; `install-and-check.md`).
- Changing the connection moves no table: moving the tables is a deploy, with a migration the application performs and
  a restart of every worker.

## Implementation Anchors

- `src/Storage/StorageConnection.php`: `name()`, `read()`, `MEMBER_KEYS`.
- `src/Storage/ConnectionAlignment.php`: `align()`, `assertAligned()`, `assertRegistered()`;
  `src/Exceptions/StorageConnectionMismatchException.php`: `forKey()`;
  `src/Exceptions/MemberNotRegisteredException.php`: `forStorage()`.
- `src/IamServiceProvider.php`: `register()`, `settle()`, `checkStorage()`, `alignStorage()`,
  `isRunningUncheckedCommand()`, `commandName()`;
  `config/iam.php`: `storage`, `transactions`.
- `src/Transactions/CrossMemberTransaction.php`: `run()`, `runInside()`, `rollBackToSavepoint()`, `isCommitted()`,
  `rolledBack()`;
  `src/Transactions/ConcurrencyFailures.php`: `isRetryable()`, `forCaller()`, `asRaised()`;
  `src/Transactions/RetrySettings.php`: `attempts()`; `src/IamManager.php`: `transaction()`.

## Authoritative Tests

- `tests/Unit/Storage/StorageConnectionTest.php`
- `tests/Feature/Storage/ConnectionAlignmentTest.php`
  `testUnsetMemberKeysReceiveTheSharedConnectionInAnyOrder`, `testAlignLeavesAMemberWhoseConfigurationIsNotMerged`,
  `testAlignLeavesAMemberWhoseProviderHasNotRegistered`, `testAKeyAnEarlierCallWroteFollowsTheSharedConnection`,
  `testAPublishedConfigurationWithoutStorageKeepsTheMembersOwnConnection`,
  `testAMemberKeyNamingAnotherConnectionRefusesBoot`, `testWithNoSharedConnectionAMemberKeyOffTheDefaultRefusesBoot`,
  `testAssertAlignedSkipsAMemberWhoseProviderHasNotRegistered`,
  `testAssertRegisteredRefusesAMemberWhoseProviderHasNotRegistered`, `testAssertRegisteredAcceptsEveryMemberRegistered`
- `tests/Feature/IamServiceProviderTest.php` `testAKeyThisPackageWroteFollowsASharedConnectionChangedLater`,
  `testAKeyThisPackageWroteFollowsASharedConnectionChangedWhileBooting`, `testAMemberKeyChangedWhileBootingRefusesBoot`,
  `testAMismatchIsNotRefusedWhileAConfigurationCommandRuns`, `testAMismatchIsRefusedWhileAnotherCommandRuns`,
  `testAMismatchIsRefusedOutsideTheConsole`,
  `testAConnectionKeyThatIsNotANameIsNotRefusedWhileAConfigurationCommandRuns`,
  `testAConnectionKeyThatIsNotANameRefusesBootWhileAnotherCommandRuns`,
  `testAMemberRegisteredWhileTheApplicationBootsIsAligned`,
  `testAMemberRegisteredWhileTheApplicationBootsRefusesAMismatch`,
  `testAMemberRegisteredWhileTheApplicationBootsKeepsItsOwnConnectionUntilItMerges`,
  `testAMemberRegisteredOnceTheApplicationHasBootedRefusesBoot`, `testALateRegistrationRefusesAMissingMemberAtOnce`,
  `testAMissingMemberIsNotRefusedWhileAConfigurationCommandRuns`
- `tests/Unit/Exceptions/StorageConnectionMismatchExceptionTest.php`,
  `tests/Unit/Exceptions/MemberNotRegisteredExceptionTest.php`
- `tests/Unit/Transactions/ConcurrencyFailuresTest.php`, `tests/Unit/Transactions/RetrySettingsTest.php`
- `tests/Integration/Transactions/CrossMemberTransactionTest.php` (through
  `tests/Concerns/RunsAtIsolationLevels.php`) `testARealSerialisationFailureIsRetriedFromTheOutermostTransaction`
  (PostgreSQL at REPEATABLE READ), `testARealDeadlockIsRetriedFromTheOutermostTransaction` (MySQL and PostgreSQL at
  READ COMMITTED and REPEATABLE READ),
  `testTheLastAttemptsFailureInAMembersTransactionReachesTheCallerAsTheDatabaseRaisedIt`,
  `testARealSerialisationFailureOnTheLastAttemptReachesTheCallerAsTheDatabaseRaisedIt` (PostgreSQL at REPEATABLE
  READ), `testARealDeadlockOnTheLastAttemptReachesTheCallerAsTheDatabaseRaisedIt` (MySQL and PostgreSQL at READ
  COMMITTED and REPEATABLE READ),
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
  `testInsideACallersRetryingTransactionASerialisationFailureIsRetriedByTheCaller`,
  `testInsideACallersTransactionTheWorksWritesAreUndoneAfterAConcurrencyFailure` and
  `testARealLockWaitTimeoutInsideACallersTransactionLeavesNoneOfTheWorksWrites` (MySQL), each as the installed Laravel
  handles the failure and as Laravel before 13.40 does (`tests/Fixtures/Transactions/SavepointLeavingConnections.php`),
  `testASavepointTheDatabaseHasAlreadyDiscardedLeavesTheWorksFailureThrownOn`,
  `testAConnectionWithoutSavepointsRollsNothingBack`, `testAFailureThatIsNotAConcurrencyFailureIsLeftToLaravelsRollback`
- `tests/Performance/Transactions/CrossMemberTransactionQueryBudgetTest.php`: one transaction or savepoint per
  attempt, counted by what became of it, and no query of the package's own.

## Change Triggers

- A member adding or renaming a storage key (`authorization.connection` included): its key joins `MEMBER_KEYS`, and its
  provider `ConnectionAlignment::MEMBER_PROVIDERS`.
- Any change to how connections are compared, to when the keys are written, or to Laravel's configuration merge.
- A change to the console's global options (another that takes a value) or its default command:
  `IamServiceProvider::commandName()` follows, and so should `laravel-mfa`'s own detection of the same commands.
- A new failure a cross-member transaction should be retried after, or a change to Laravel's concurrency detector or to
  how it wraps a failure inside a nested transaction, rolls back to its savepoint or names it.
- The floor moving to Laravel 13.40 or later, where the nested transaction rolls back to its savepoint itself:
  `rollBackToSavepoint()` can go.
- Any use case that writes two members' tables outside `CrossMemberTransaction`.
