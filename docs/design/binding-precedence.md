# Binding Precedence

## Purpose

This note describes how the package binds its adapters over the members' seams without ever replacing a binding the
application made, whatever order the service providers register in (IAM-8.4), why the rule runs from a `booting()`
callback rather than from `register()`, and how a member's own default is told apart from the application's binding.

## Invariants

- Everything the package binds over a member's seam is declared as data, one `Bindings\SeamBinding` per seam: the
  member's contract, the package's adapter, the member's own defaults, a `Bindings\Enums\Lifetime`, an optional switch
  and whether the seam is mandatory. Each capability lists its rows in a `*Seams` class implementing
  `Bindings\Contracts\ProvidesSeams`, named in `IamServiceProvider::seamProviders()`, and one `Bindings\BindingRule`
  applies them all. Nothing is bound over a member from a `register()` or a `boot()`. M1 lists no capability: it ships
  the rule, and each later milestone adds its rows.
- The rule runs once, from a `booting()` callback that `IamServiceProvider::register()` registers: after every
  provider's `register()` and before any provider's `boot()`, since Laravel fires the application's booting callbacks
  before it boots the first provider, whichever provider registered them. Composer discovers providers sorted by
  package name, so this package registers after `laravel-audit-log`, `laravel-authentication` and
  `laravel-authorization` and before `laravel-mfa` and `laravel-sso`. `laravel-mfa` bound its defaults with a plain
  `bind()` until laravel-mfa#90, which would have overwritten a binding made in this package's `register()` in that
  order and in no other; the `dev-master` installed now binds them with `bindIf()`. The rule stays in the booting
  phase until IAM-13.11 is recorded done and the members' constraint pins a release that includes #90, and waiting
  for it still makes the order irrelevant against any member or third-party provider that binds over a seam with a
  plain `bind()` or `singleton()` (`laravel-authorization` binds its resolvers with a plain `singleton()`).
- A seam is bound only where `Bindings\MemberDefaults::isReplaceable()` allows it: the seam is unbound, or the
  container's binding table shows it still bound to one of the member's defaults the row declares. No member exposes
  its defaults as data, so the table (`Container::getBindings()`) is the only public source:
  - "Unbound" is `bound()`, which also counts instances, aliases and, on the application, deferred services, so none
    of them looks unbound because it is missing from the table.
  - A class-string binding is held as the closure Laravel's `getClosure()` builds around it, which carries the class
    it was given as its `concrete` used variable; that class is compared with the declared defaults.
  - A closure binding carries the class that lexically declares it as its scope class, static or not; that class is
    compared instead. Members declare closures outside their providers too (`laravel-mfa`'s `ProofStore` default is
    declared in `Mfa\Proofs\ProofBindings`), so a row names the declaring class, never the provider by assumption.
- Anything else is the application's and is kept: an instance or an alias (Laravel's `instance()` and `alias()` leave
  the binding beneath them in the table, and binding over either would drop the application's, so `isAlias()` is
  checked before the table is read), a shared default something has already resolved (whatever resolved it holds that
  instance, which a new binding would not replace), a closure the application declares, a class-string binding to any
  class the row does not name, and every binding in a container without a table to read.
- An allowed seam is bound with its row's lifetime: `TRANSIENT` with `bind()`, `SHARED` with `singleton()`, `SCOPED`
  with `scoped()`. Adapters are transient unless a requirement names a lifetime; one that holds request state is
  scoped, never shared (IAM-8.1).
- A row whose switch (`appliesWhen`, a closure over the configuration repository) answers `false` binds nothing and
  checks nothing (IAM-1.3), and the outcome lists it neither as bound nor as kept. The switch is read once, in the
  booting phase, like the rest of the rule.
- What the rule did is a `Bindings\BindingOutcome`, the seams bound and the seams kept in the order of the rows, which
  `IamServiceProvider::settle()` keeps in the container for `iam:check` to report (M8).
- `settle()` runs once per provider, whichever phase reaches it first: the booting callback, or the provider's own
  `boot()` when it was registered after the booting callbacks have run.

## Success Path

- An application binds nothing: every seam whose switch is on gets the package's adapter with its lifetime.
- An application binds a seam in a `register()` of its own: Laravel registers the application's providers after every
  package's, so in whatever order the packages register, the rule finds the application's binding and keeps it.
- An application binds a seam in a `boot()`: the binding lands after the rule and replaces the adapter, as any later
  binding does.
- An application aliases a seam to a binding of its own in a `register()`: the alias is kept, though the member's
  default stays beneath it in the binding table.
- A provider that registers this package after the application has booted (`$app->register()` late) gets the same
  rule at once: a booting callback registered then would never run, so `registerBindingRule()` registers none, and
  Laravel boots the provider at once, whose `boot()` settles.
- A provider that registers this package from its own `boot()` registers it after Laravel has fired the booting
  callbacks but before the application has booted, so the callback it queues would never run either. Laravel still
  boots the provider, and its `boot()` settles: the rule applies there, and bindings made in the `boot()` of providers
  that booted earlier are treated as the application's and kept.

## Failure / Edge Cases

- A member renaming a default's class, or moving a closure binding to another class, makes the rule treat the new
  default as the application's and keep it. That fails closed: no adapter is bound over a binding the rule cannot
  recognise, and `iam:check` (M8) reports a mandatory seam left on its permissive default at deploy. The tests pin the
  members' defaults, in every provider order, on every supported Laravel version.
- An application that binds a seam to the member's own default class by name is indistinguishable from the member and
  gets the adapter. To keep the member's default deliberately, turn the row's switch off, or bind the default with a
  closure or an instance.
- A provider that registers before the members (one listed ahead of the package manifest) keeps its binding of a seam
  the member binds conditionally, but a member that binds with a plain `bind()` or `singleton()` replaces it first.
  That seam is then the member's default again, and the rule binds the adapter over it. Bind seams from a provider
  Laravel registers after the packages, as it registers the application's own.
- Resolving a shared member seam while providers are still registering keeps the member's default, since the resolved
  instance is kept. Resolve nothing while registering.
- The detection depends on the shape of Laravel's `getClosure()` closure (`use ($abstract, $concrete)`), identical from
  Laravel 12 to 13; a Laravel version that changes it would make every class-string default look like the
  application's, and the rule would keep them all, failing closed, until the detection is updated.
- The storage connection is aligned and checked in the same booting callback, before the rule applies; see
  `storage-and-transactions.md`.

## Implementation Anchors

- `src/IamServiceProvider.php`: `register()`, `boot()`, `registerBindingRule()`, `settle()`, `seamProviders()`.
- `src/Bindings/BindingRule.php`: `apply()`; `src/Bindings/MemberDefaults.php`: `isReplaceable()`.
- `src/Bindings/SeamBinding.php`, `src/Bindings/Enums/Lifetime.php`, `src/Bindings/BindingOutcome.php`,
  `src/Bindings/Contracts/ProvidesSeams.php`.
- `benchmarks/Bindings/BindingRuleBench.php`: the rule over a 40-seam table on the members' real binding table, binding
  over their defaults, keeping the application's bindings, and with every switch off.

## Authoritative Tests

- `tests/Feature/Bindings/BindingRuleTest.php` (through `tests/Concerns/PermutesProviderOrder.php`)
  `testTheAdapterIsBoundOverEveryMemberDefaultInEveryProviderOrder`,
  `testAnApplicationBindingMadeOnceEveryProviderHasRegisteredIsKept`,
  `testAnApplicationProviderRegisteredAfterThePackagesIsKept`,
  `testAnApplicationProviderRegisteredBeforeThePackagesIsKeptWhereTheMemberLeavesIt`,
  `testAnApplicationBindingMadeInBootReplacesTheAdapter`, `testAnInstanceIsKept`, `testAnApplicationAliasIsKept`,
  `testEachAdapterIsBoundWithItsLifetime`, `testTheRuleAppliesAtOnceWhenRegisteredAfterBoot`,
  `testTheRuleAppliesWhenRegisteredWhileTheApplicationBoots`, `testABindingWhoseSwitchIsOffBindsNothing`,
  `testTheOutcomeListsTheSeamsBoundAndKeptInOrder`
- `tests/Feature/IamServiceProviderTest.php` `testARegistrationWhileTheApplicationBootsSettlesFromItsOwnBoot`,
  `testALateRegistrationSettlesAtOnceAndLeavesNoBootingCallback`, `testThePackageSettlesOnlyOnce`
- `tests/Unit/Bindings/MemberDefaultsTest.php`
- `tests/Unit/Bindings/SeamBindingTest.php`, `tests/Unit/Bindings/BindingOutcomeTest.php`,
  `tests/Unit/Bindings/Enums/LifetimeTest.php`

## Change Triggers

- A new seam binding: its row in a capability's `*Seams` class, with every default the member binds it to, and its
  capability named in `seamProviders()`.
- A member changing how it binds a seam (a new default class, a closure moved to another class, plain `bind()` turning
  into `bindIf()`), and in particular a tagged `laravel-mfa` release that includes laravel-mfa#90 (its `bindIf()`
  defaults) being pinned by the members' constraint and IAM-13.11 recorded done, which lets the rule run in
  `register()`.
- A new supported Laravel version, or any change to `getClosure()`, `getBindings()`, `bound()` or the booting order.
