# Binding Precedence

## Purpose

This note describes how the package binds its adapters over the members' seams without ever replacing a binding the
application made, whatever order the service providers register in (IAM-8.4), why the rule runs in `register()`, how a
member's own default is told apart from the application's binding, how the switches read a member's configuration
before that member has merged it, and why the storage connection alone still waits for a `booting()` callback.

## Invariants

- Everything the package binds over a member's seam is declared as data, one `Bindings\SeamBinding` per seam: the
  member's contract, the package's adapter, the member's own defaults, a `Bindings\Enums\Lifetime`, an optional switch
  and whether the seam is mandatory, a flag or a closure the checks ask as they read it (`SeamBinding::isMandatory()`),
  so a mandate that asks a service the application binds never resolves it while the rule runs. Each capability lists
  its rows in a `*Seams` class implementing `Bindings\Contracts\ProvidesSeams`, named in
  `IamServiceProvider::seamProviders()`, and one `Bindings\BindingRule` collects every capability's rows (`apply()`)
  and applies them all. Nothing else in the package binds over a member.
  M1 lists no capability: it ships the rule, and each later milestone adds its rows.
- The rule runs over every row once, in `IamServiceProvider::register()` (`registerSeams()`), whenever the provider
  registers: with the other package providers, while the application boots, or after it has booted. Only the tenancy
  rows that pass left open are applied once more, from the booting phase (below).
- Every member binds its defaults only where nothing is bound yet, with `bindIf()`, `singletonIf()` or `scopedIf()`
  (`laravel-mfa` since laravel-mfa#92, IAM-13.11), so the order the providers register in decides nothing:
  - A member that registers before this package has bound its default by then; the rule recognises it from the
    container's binding table and binds the adapter over it.
  - A member that registers after this package finds the adapter bound and leaves it in place.
  - Composer discovers providers sorted by package name, so this package registers after `laravel-audit-log`,
    `laravel-authentication` and `laravel-authorization` and before `laravel-mfa` and `laravel-sso`; both cases occur
    in a default installation.
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
- An application binding made after the rule runs, in a later `register()` or in any `boot()`, replaces the adapter as
  any later binding does. So the application's binding wins whether it is made before this package registers (kept)
  or after (replacing).
- An allowed seam is bound with its row's lifetime: `TRANSIENT` with `bind()`, `SHARED` with `singleton()`. Adapters
  are transient unless a requirement names a lifetime; one that holds request state is scoped, never shared (IAM-8.1).
- A `SCOPED` adapter is never scoped under the member's seam itself (`BindingRule::bindScoped()`):
  - Laravel's `scoped()` adds the abstract to the container's list of scoped instances for good, and the queue worker
    (before each job) and Octane (after each request) forget every instance held under an abstract on that list. An
    instance or a singleton the application bound over the seam after the rule ran would be dropped, and the adapter
    would resolve again from the second job or request on, so a later application binding would not win.
  - So the adapter is scoped under a key this package owns, `iam.scoped:` followed by the seam
    (`BindingRule::SCOPED_PREFIX`), and the seam is bound with a transient closure that resolves that key, as
    `laravel-authorization` scopes its own defaults (`scoped($default)` with `bind($contract, fn => make($default))`).
    The adapter is still built once per request or job, and a binding the application makes over the seam later is
    never on the scoped list (`testAnInstanceMadeOverAScopedAdapterOutlivesTheScopedInstances`,
    `testASingletonMadeOverAScopedAdapterStaysShared`).
  - A member that registers before this package and binds its default with `scopedIf()`, as `laravel-sso` does, has
    put the seam on that list already, and binding over it leaves it there. So, whatever the row's lifetime, the rule
    takes the seam off the list before binding over it (`BindingRule::unscope()`, which reads the container's protected
    `scopedInstances` as `WorkerReset` does). Otherwise a shared adapter would be built again for every request and
    job, and an application instance made later would still be dropped in that provider order
    (`testASharedAdapterBoundOverAScopedDefaultStaysShared`). The list is filtered by strict comparison, never with
    `array_diff()`: for a binding scoped by its closure's return type (`scoped(fn (): Foo => ...)`), Laravel lists the
    closure itself, which `array_diff()` cannot convert to a string, and any provider that registers before this
    package can make one. Such an entry is kept on the list
    (`testAScopedBindingKeyedByItsClosureStaysScoped`).
- A row whose switch (`appliesWhen`, a closure over the configuration repository) answers `false` binds nothing and
  checks nothing (IAM-1.3), and the outcome lists it neither as bound nor as kept. The switch is read once, as the rule
  runs in `register()`, and so is each capability's `seams()`, both from the configuration every member will hold once
  registered (`BindingRule::switches()`), so a switch on a member's own feature (`sso.features`, MFA's factor types,
  as the Seam Readiness row for IAM-1.3 places them) reads the same in every provider order:
  - Laravel loads the application's configuration files and environment before any provider registers, but a member
    merges its packaged configuration, the defaults and its own `env()` values among it, only in its own `register()`.
    Composer registers `laravel-mfa` and `laravel-sso` after this package, so their keys would read as unset here in a
    default installation, and the same application would bind otherwise with its configuration cached (where every
    member's keys are present from the start) and not.
  - So the rule reads a copy of the application's configuration with the packaged file of each member that has not
    registered yet (`config/<key>.php` beside the member's provider) merged beneath it one level deep, exactly as that
    member's `mergeConfigFrom()` will merge it: the application's own values win, and the file's `env()` calls read the
    same environment. A member that has registered has merged its file already and is not read again. The
    application's configuration is never written.
  - A cached configuration is read as it is: it holds what every member merged when it was cached, and Laravel merges
    nothing over it, so nothing is filled in that the members themselves would not see.
  - A value a provider registered after this package sets, or any `boot()` sets, is still read too late; set switches
    in configuration files or the environment.
- What the rule did is a `Bindings\BindingOutcome`, the seams bound and the seams kept in the order of the rows, which
  `IamServiceProvider::registerSeams()` keeps in the container for `iam:check` to report. It records the rule's
  own decision as it ran; a binding made afterwards replaces the adapter without changing it, so the check reads the
  live binding of each mandatory seam as well (`Checks\MandatorySeamsCheck`, `install-and-check.md`).
- The rule is applied once more from the booting phase, to the rows the first pass left open and only those
  (`BindingRule::applyAgain()`, from `IamServiceProvider::settle()`): the tenancy rows `Tenancy\TenancySeams` declares
  over SSO's `TenantMembership`, `LinkEligibility`, `PrincipalScope` and `EnforcementInheritance`
  (`provisioning-and-tenancy.md`), whose switch reads the container as well as the configuration. Memberships or a
  tenant tree an application binds in its own provider's `register()`, which Laravel runs after the packages', are there
  only then, so the callback binds the adapters they answer over SSO's defaults, and an application's own binding of
  SSO's seam made by then is kept; the outcome kept for the checks gains them. A seam the first pass bound or kept is
  not decided again. Because a class-string binding to SSO's default class made by the application reads, by its class,
  exactly as SSO's own, the first pass reserves each of these rows it leaves off (`BindingRule::reserve()`): the exact
  closure the seam holds for SSO's default is recorded in the outcome, and where SSO has not registered yet, SSO's
  default is bound there first, shared, as SSO's `singletonIf()` would bind it, which SSO's own binding then leaves.
  Applied again, the rule binds over a seam only while it holds exactly that closure (`MemberDefaults::bindingOf()`);
  one bound over since, whatever its class, is the application's and is kept. It runs only while `iam.adapters.sso` was
  on when the rule first read it, and the rows follow the switch as it read then, so a value a later provider writes
  still comes too late, off as much as on, and SSO's seams and these rows are bound together or not at all. Nothing else
  is bound from the booting phase: the callback that once applied the whole rule there, while `laravel-mfa` still bound
  its defaults unconditionally, is gone.
- One more step waits for the booting phase: the storage connection (`storage-and-transactions.md`), which binds
  nothing. It stays for reasons of its own:
  - A member key is written, unlike a switch, which is only read, and it can be written only once the member has merged
    its configuration: a key written before would make the member's `mergeConfigFrom()` keep the application's
    `storage` block whole, dropping the member's other storage keys and their environment values. A member that
    registers after this package merges only then.
  - An application provider registered after this package may name another shared connection, which the member keys
    must follow, and `assertAligned()` can refuse a mismatch only once no `register()` can change a key any more.
  - So `register()` aligns what it can and queues one `booting()` callback, which Laravel fires once every provider
    registered with the others has registered and before the first boots; `settle()` aligns the rest and checks, once
    per provider, from that callback or from the provider's own `boot()` when it registered after the callbacks had
    run.
  - A `boot()` can still register a member (which merges its configuration only then), name another shared connection
    or point a member key elsewhere, so the booting phase is not the end of it: `settle()` queues one `booted()`
    callback that aligns and checks once more when the application has booted, and refuses a member whose provider has
    still not registered (`MemberNotRegisteredException`), since its key could never be aligned and the package
    requires every member (IAM-1.3). A member registered while the application boots is left, key and check, for that
    callback; one registered once it has booted is refused, its key never having been checked.

## Success Path

- An application binds nothing: every seam whose switch is on gets the package's adapter with its lifetime.
- An application binds a seam in a `register()` of its own: Laravel registers the application's providers after every
  package's, so the binding lands after the rule and replaces the adapter, and the members, binding only what is
  unbound, leave it in place.
- An application binds a seam in a provider that registers before this package's: the rule finds the application's
  binding and keeps it, and the members leave it in place.
- An application binds its memberships or tenant tree in a `register()` of its own, with `iam.adapters.sso` on as
  this package registered: the booting callback applies the tenancy rows again and binds SSO's tenancy adapters over
  SSO's defaults; a binding of SSO's seam it made there too is kept.
- An application binds a seam in a `boot()`: the binding lands after the rule and replaces the adapter.
- An application aliases a seam or binds an instance: before this package registers, it is kept; after, it wins.
- A provider that registers this package while the application boots, or after it has booted, gets the same rule as
  it registers, and settles the storage connection from its own `boot()`, which Laravel runs for it then: a booting
  callback queued at that point would never run, so `registerStorageCheck()` queues none once the application has
  booted. The `booted()` callback `settle()` queues then runs once the application has booted, or at once when it
  already has.
- A provider that registers a member from its own `boot()` has the member's binding defaults yield to the adapters
  (every member binds with `bindIf()`, `singletonIf()` or `scopedIf()`), and the member's storage key aligned and
  checked once the application has booted.

## Failure / Edge Cases

- A provider that binds a seam unconditionally (`bind()`, `singleton()`) after this package registers replaces the
  adapter, member or not, though the outcome lists the seam as bound. `laravel-authorization` still binds its defaults
  unconditionally (IAM-13.7; since laravel-authorization#72 with a plain `bind()` of a closure its provider declares,
  over a scoped `authorization.default:` binding holding the class its configuration names), so its rows name that
  key (`SeamBinding::$defaultKey`): the seam is the member's only while the closure is its provider's and the key still
  holds its default class (or an instance of exactly that class resolved there, as its boot leaves one), never a class
  the application names in its configuration. The seams the rule bound are bound again from the booting callback, and
  once more from the `booted()` callback for a member registered from a provider's `boot()`, where they hold that
  member's closure once more (`BindingRule::reclaim()`, `MemberDefaults::holdsDefault()`), a binding of the member's
  default class by name being the application's (`authorization.md`); when the `booted()` pass binds any seam again,
  what was resolved from the defaults meanwhile is forgotten (`WorkerReset::forgetScopedState()`) and the context's
  keys are declared on a key catalogue already built. The seams the rule kept with the application's
  binding over such a member are recorded as the rule runs, with what binds that binding again
  (`MemberDefaults::restorerOf()`, `BindingOutcome::$restorers`: an alias, an instance, or the closure, shared as it
  was), and bound back the same way. `iam:check` refuses any of these seams the outcome lists that holds the member's
  own default again once neither callback can run (`MandatorySeamsCheck`). Any other member that bound unconditionally
  after this package would still replace the adapter. One that binds unconditionally before this package registers
  replaces any application binding made before it, and the rule then binds the adapter over that member default; so
  does one registering between this package and an application binding made after this package registered and before
  that member.
- A member renaming a default's class, or moving a closure binding to another class, makes the rule treat the new
  default as the application's and keep it. That fails closed: no adapter is bound over a binding the rule cannot
  recognise, and `iam:check` reports a mandatory seam left on any class of its member's own at deploy. The tests pin the
  members' defaults, in every provider order, on every supported Laravel version.
- An application that binds a seam to the member's own default class by name, before this package registers, is
  indistinguishable from the member and gets the adapter. To keep the member's default deliberately, turn the row's
  switch off, or bind the default with a closure or an instance.
- A switch the application sets from a provider's `register()` after this package's, or from any `boot()`, is read too
  late to change what the rule bound. Set switches in configuration files or the environment.
- A member that never registers (left out of package discovery and never registered by hand) still has its packaged
  configuration read for the switches, as if it would; the package requires all five members (IAM-1.3), so this only
  happens to an application that removes one deliberately. One whose storage this package aligns
  (`laravel-authentication`, `laravel-mfa`, `laravel-sso`) refuses boot once the application has booted, and so does
  one registered only after that, except while a configuration command runs (`storage-and-transactions.md`).
- A configuration cached while a member's block was missing reads that block as missing, as the member itself then
  does; caching it again once every member is installed fills it.
- Resolving a shared member seam before this package registers keeps the member's default, since the resolved instance
  is kept. Resolve nothing while registering.
- The detection depends on the shape of Laravel's `getClosure()` closure (`use ($abstract, $concrete)`), identical from
  Laravel 12 to 13; a Laravel version that changes it would make every class-string default look like the
  application's, and the rule would keep them all, failing closed, until the detection is updated.

## Implementation Anchors

- `src/IamServiceProvider.php`: `register()`, `registerSeams()`, `seamProviders()`; `registerStorageCheck()`,
  `settle()` (which also applies the tenancy rows again, with the SSO switch as it read in `registerSeams()`),
  `checkStorage()` and `boot()` for the storage step that waits for the booting phase and runs again once the
  application has booted.
- `src/Bindings/BindingRule.php`: `apply()`, `reserve()`, `applyAgain()`, `reclaim()`, `switches()`,
  `MEMBER_CONFIGURATION`; `src/Bindings/MemberDefaults.php`: `isReplaceable()`, `holdsDefault()`, `bindingOf()`,
  `restorerOf()`;
  `src/Tenancy/TenancySeams.php` for the rows applied again, `src/Authorization/AuthorizationSeams.php` for the rows
  bound again.
- `src/Bindings/SeamBinding.php`, `src/Bindings/Enums/Lifetime.php`, `src/Bindings/BindingOutcome.php`,
  `src/Bindings/Contracts/ProvidesSeams.php`.
- `benchmarks/Bindings/BindingRuleBench.php`: the rule over a 40-seam table on the members' real binding table, binding
  over their defaults, keeping the application's bindings, and with every switch off, the switches read from an
  uncached configuration.

## Authoritative Tests

- `tests/Feature/Bindings/BindingRuleTest.php` (through `tests/Concerns/PermutesProviderOrder.php`, with fixture
  members binding with `bindIf()`, `singletonIf()` and `scopedIf()`, and a fixture seam switched by
  `sso.features.metadata_refresh`, which only `laravel-sso`'s own packaged file and `SSO_METADATA_REFRESH` fill)
  `testTheAdapterIsBoundOverEveryMemberDefaultInEveryProviderOrder`,
  `testAnApplicationBindingMadeBeforeAnyProviderRegistersIsKept`,
  `testAnApplicationBindingMadeOnceEveryProviderHasRegisteredWins`,
  `testAnApplicationProviderRegisteredBeforeThePackagesIsKept`,
  `testAnApplicationProviderRegisteredStraightBeforeThisPackageIsKept`,
  `testAnApplicationProviderRegisteredStraightAfterThisPackageWins`,
  `testAnApplicationProviderRegisteredAfterThePackagesWins`, `testAnApplicationBindingMadeInBootWins`,
  `testAnInstanceMadeBeforeAnyProviderRegistersIsKept`, `testAnInstanceMadeOnceEveryProviderHasRegisteredWins`,
  `testAnApplicationAliasMadeBeforeThePackagesIsKept`, `testAnApplicationAliasMadeAfterThePackagesWins`,
  `testASwitchTheConfigurationTurnsOffBindsNothing`, `testASwitchTurnedOffOnceEveryProviderHasRegisteredIsNotRead`,
  `testAPlainDefaultBoundBeforeThisPackageRegistersIsReplaced`,
  `testAPlainDefaultBoundAfterThisPackageRegistersReplacesTheAdapter`,
  `testAPlainDefaultReplacesAnApplicationBindingMadeBeforeIt`, `testEachAdapterIsBoundWithItsLifetime`,
  `testASharedAdapterBoundOverAScopedDefaultStaysShared`, `testAScopedBindingKeyedByItsClosureStaysScoped`,
  `testTheRuleAppliesAtOnceWhenRegisteredAfterBoot`, `testTheRuleKeepsASharedDefaultResolvedBeforeItApplies`,
  `testABindingWhoseSwitchIsOffBindsNothing`, `testTheOutcomeListsTheSeamsBoundAndKeptInOrder`,
  `testAMembersSwitchItsPackagedConfigurationTurnsOnBindsInEveryProviderOrder`,
  `testAMembersSwitchItsEnvironmentTurnsOffBindsNothingInEveryProviderOrder`,
  `testAMembersSwitchTheApplicationsConfigurationTurnsOffBindsNothingInEveryProviderOrder`,
  `testTheSwitchesReadEveryMembersConfigurationAsTheBootedApplicationHoldsIt` (each in every provider order, the
  first, second and fourth with the configuration cached too), `testACachedConfigurationIsReadAsItIs`,
  `testAnApplicationThatCannotCacheItsConfigurationHasTheMembersPackagedConfigurationRead`,
  `testApplyingAgainDecidesOnlyWhatTheOutcomeLeftOpen`, `testReservingRecordsTheMembersDefaultEachSeamHolds`,
  `testReclaimingBindsAgainTheApplicationsBindingAMemberBoundItsDefaultOver`,
  `testABindingMadeOverAReservedSeamIsKept`
- `tests/Feature/Tenancy/TenancySeamsTest.php` (the rows applied again from the booting phase, by register order)
  `testMembershipsAndATreeBoundAfterRegisteringBindTheAdapters`,
  `testAnApplicationProviderBindingTenancyWhileRegisteringBindsTheAdapters`,
  `testAnApplicationsOwnBindingMadeAfterRegisteringIsKept`,
  `testAnApplicationsBindingOfSsosDefaultClassMadeWithItsTenancyIsKept`,
  `testMembershipsAndATreeBoundWhileBootingBindNothing`,
  `testWithTheSsoSwitchOffTenancyBoundLaterBindsNothing`, `testTheSsoSwitchTurnedOnAfterRegisteringBindsNoTenancy`,
  `testTheSsoSwitchTurnedOffAfterRegisteringStillBindsTheTenancy`
- `tests/Feature/IamServiceProviderTest.php` `testTheBindingRuleAppliesAsThePackageRegisters`,
  `testThePackageSettlesBeforeAnyProviderBoots`, `testARegistrationWhileTheApplicationBootsAppliesTheBindingRule`,
  `testALateRegistrationSettlesAtOnceAndLeavesNoBootingCallback`, `testThePackageSettlesOnlyOnce`,
  `testAMemberRegisteredWhileTheApplicationBootsIsAligned`,
  `testAMemberRegisteredOnceTheApplicationHasBootedRefusesBoot`, `testALateRegistrationRefusesAMissingMemberAtOnce`
- `tests/Unit/Bindings/MemberDefaultsTest.php`
- `tests/Unit/Bindings/SeamBindingTest.php`, `tests/Unit/Bindings/BindingOutcomeTest.php`,
  `tests/Unit/Bindings/Enums/LifetimeTest.php`

## Change Triggers

- A new seam binding: its row in a capability's `*Seams` class, with every default the member binds it to, and its
  capability named in `seamProviders()`.
- A member changing how it binds a seam (a new default class, a closure moved to another class, a conditional binding
  turning unconditional), and in particular `laravel-authorization` moving its defaults to a conditional binding
  (IAM-13.7), after which `BindingRule::reclaim()` has nothing left to do for it.
- A member whose configuration stops being merged in its own `register()`, or that starts reading its storage
  connection eagerly (before the application has booted, when a member registered while it boots is aligned), which
  changes what the storage step in the booting phase must do.
- A member moving its packaged configuration file, merging it under another key, merging more than one file, or a new
  member: `BindingRule::MEMBER_CONFIGURATION` follows. Laravel changing how `mergeConfigFrom()` merges (one level
  deep, skipped with a cached configuration): `BindingRule::switches()` follows.
- A new supported Laravel version, or any change to `getClosure()`, `getBindings()`, `bound()` or the order Laravel
  registers and boots providers in.
