# Design Notes

These notes document the package's security and lifecycle contracts that are easy to miss if you only read the
quick-start material or skim the test suite.

Each note is intentionally short and follows the same structure:

- `Purpose`
- `Invariants`
- `Success Path`
- `Failure / Edge Cases`
- `Implementation Anchors`
- `Authoritative Tests`
- `Change Triggers`

The current note set is:

- `binding-precedence.md`: how the package binds its adapters over the members' seams once, in `register()`, only where
  a seam is unbound or still the member's own default, so the application's binding wins whatever order the providers
  register in; how a member's default is told from the container's binding table; the lifetimes and the switches, read
  with each member's packaged configuration beneath the application's; and why the storage connection alone still
  waits for a `booting()` callback.
- `storage-and-transactions.md`: the one storage connection every member is aligned to and the boot refusal of a
  member on another, and how a change that spans members runs in one transaction on it, retried as a whole after a
  concurrency failure only when the package opened the outermost transaction, and rolled back to its savepoint inside
  a caller's.
- `long-running-processes.md`: the combined worker reset that flushes every member's request state, the session that
  holds MFA's proofs among it, what it flushes before each Octane request and each queued job, why a job keeps its
  scoped instances and the application keeps its own instances, and how another long-lived process calls it.
- `authentication-and-mfa.md`: the twelve seams between `laravel-authentication` and `laravel-mfa` and the default
  each replaces; how an MFA application and sign-in are resolved to a guard and its current session, and refused when
  they cannot be; how proofs, channels, requirements, levels and changes are translated, `external_reauthentication`
  and `unclassified` among them; what each adapter answers and how it refuses; the evaluation a further proof is
  recorded with; and the lock order, identity state and factors before the session row, with what each isolation level
  does to a change that waited and why MFA's changes are never wrapped in another transaction.

A note is added here with the code it describes.

These documents are secondary to the code and tests, not a replacement for them. If a note and a cited test disagree,
the test should be treated as authoritative until the mismatch is resolved.
