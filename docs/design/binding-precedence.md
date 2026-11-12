# Binding Precedence

How the package binds its adapters over the members' seams without replacing a binding the application made.

## Decisions

- Each capability lists its seams as `SeamBinding` rows in a `*Seams` class: the member's contract, the adapter, the
  switch that binds it, its `Lifetime` and whether `iam:check` treats it as mandatory.
- The rows are applied once from a `booting()` callback, after every provider has registered and before any boots. A
  provider registered later applies them from its own `boot()`.
- A row binds its adapter only where the seam is unbound or the member's `isPackageDefault()` says it still holds the
  member's default. The member decides, so the package never guesses at another package's bindings.
- A scoped adapter is held under `iam.scoped:<seam>` and the seam binds a transient closure resolving that key, so the
  worker reset finds the package's state by the prefix.
- An adapter over a `laravel-authorization` contract is declared to its configuration report, so `authorization:check`
  names it.

## Invariants

- An application binding made in any `register()` is kept, whatever order the providers register in; one made in a
  `boot()` replaces the adapter.
- `iam:check` refuses a mandatory seam that is unbound or still holds its member's default.

## Member gaps

None.
