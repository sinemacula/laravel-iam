# Binding Precedence

## Purpose

How the package binds its adapters over the members' seams without replacing a binding the application made
(IAM-8.4).

## Rule

- Each capability lists its seams as `Bindings\SeamBinding` rows in a `*Seams` class
  (`IamServiceProvider::seamProviders()`): the member's contract, the adapter, whether the capability's switch binds
  it, its `Lifetime` and whether `iam:check` treats it as mandatory.
- The rows are applied once, from a `booting()` callback, after every provider has registered and before any boots
  (`IamServiceProvider::bindSeams()`). A provider registered after that phase applies them from its own `boot()`.
- A row binds its adapter where the seam is unbound or where the member says the seam still holds its own default,
  through that member's public `isPackageDefault()` (`SeamBinding::holdsDefault()`). Anything else is the
  application's binding and is kept.
- So an application binding made in any `register()`, before or after the packages', is kept whatever order the
  providers register in, and one made in a `boot()` replaces the adapter.
- A scoped adapter is held under `iam.scoped:` followed by the seam (`SeamBinding::SCOPED_PREFIX`), and the seam is
  bound to a transient closure resolving that key, so the seam itself never joins the container's scoped instances and
  the worker reset finds the package's state by the prefix.
- An adapter bound over a `laravel-authorization` contract is declared to its configuration report with the closure
  bound, so `authorization:check` names it until something replaces it.
- `iam:check` refuses a mandatory seam that is unbound or that its member says still holds its default
  (`Checks\MandatorySeamsCheck`); any other binding passes.

## Change triggers

- A member changes what its `isPackageDefault()` answers, or how it binds its defaults.
- A capability adds, removes or renames a seam: its `*Seams` table follows.
