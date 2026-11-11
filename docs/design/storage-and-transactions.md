# Storage and Transactions

## Storage connection

Every member keeps its tables on the one connection `iam.storage.connection` names (IAM-2.3), so a change that spans
members can commit as one. `Storage\ConnectionAlignment` writes that connection into each member key left unset
(`StorageConnection::MEMBER_KEYS`), and boot is refused with `StorageConnectionMismatchException` when a member key names
another. The check is skipped while a configuration command runs, so a bad value can still be cleared. `iam:check`
checks that the identity models the guards use are on it too.

## Cross-member transactions

`Iam::transaction()` (`Transactions\CrossMemberTransaction`) runs the work through Laravel's own
`transaction($work, $attempts)` on the storage connection (IAM-11.1, IAM-11.2):

- Only the outermost transaction retries, up to `iam.transactions.attempts`; Laravel never retries a nested one, so
  inside a transaction the caller opened the failure is rethrown for the caller to retry.
- A concurrency failure anywhere in the exception's chain, SSO's `LinkCandidatesChanged` included, is rethrown as a
  `DeadlockException` with SQLSTATE 40001 as its code. Laravel's detector misses `LinkCandidatesChanged`, and a nested
  transaction drops a string SQLSTATE, which PostgreSQL's serialisation failure needs to be recognised.
- A failure after the commit, from an after-commit callback, is never retried.
- Flows whose transaction a member opens itself are not wrapped: MFA's verifications and factor changes, and SSO's
  standalone `link`. The caller retries the request.

On Laravel before 13.40, a concurrency failure in a nested transaction does not roll back to its savepoint, and on
Laravel 12 a retried commit failure can run the failed attempt's after-commit callbacks too. Both are Laravel's
behaviour for every transaction; the package adds nothing over them.

## After commit

Laravel's `afterCommit()` waits on whichever connection opened a transaction last. `Transactions\AfterConnectionCommits`
holds work for one connection's commit and runs it on `TransactionCommitted`, once every callback of that commit has
run, since laravel-sso drops its own after-commit events once an earlier callback of the same commit begins a
transaction. The tenant policy's second pass and the deferred audit refusals use it; `Transactions\OpenTransactions`
lists the transactions open on one connection, for a rollback callback on each, as Laravel 12 does not tell a committed
savepoint of its parent's rollback.
