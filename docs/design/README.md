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

- `binding-precedence.md`: how the package binds its adapters over the members' seams once, from a `booting()`
  callback, only where a seam is unbound or still the member's own default, so the application's binding wins whatever
  order the providers register in; how a member's default is told from the container's binding table; the lifetimes
  and the switches.
- `storage-and-transactions.md`: the one storage connection every member is aligned to and the boot refusal of a
  member on another, and how a change that spans members runs in one transaction on it, retried as a whole after a
  concurrency failure only when the package opened the outermost transaction.
- `long-running-processes.md`: the combined worker reset that flushes every member's request state, what it flushes
  before each Octane request and each queued job, why a job keeps its scoped instances, and how another long-lived
  process calls it.

A note is added here with the code it describes.

These documents are secondary to the code and tests, not a replacement for them. If a note and a cited test disagree,
the test should be treated as authoritative until the mismatch is resolved.
