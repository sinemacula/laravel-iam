# Install and Check

## Purpose

This note describes how `iam:install` publishes every member's files and this package's configuration into an
application, recognising what is already there (IAM-2.1, IAM-2.4); how `Iam::schedule()` registers the members'
scheduled work they leave to the application (IAM-2.6); the PHP extensions this package declares (IAM-2.8); how
`iam:check` runs every member's check and this package's own (IAM-10); what `laravel-authorization`'s glue adds to both;
and the gaps in the members it works around.

## Invariants

### Installation (IAM-2.1, IAM-2.4)

- `Console\InstallCommand` (`iam:install`) publishes every member's `-config` and `-lang` tags, and this package's
  `iam-config`, through Laravel's `vendor:publish`, which keeps a file already there.
- Each member's `-migrations` tag is expanded to its files and filtered through `Install\MigrationLedger`, since
  `vendor:publish` compares only a whole file name: a migration is already published when a file beside its
  destination shares its base name (its file name without the timestamp) and names the member's namespace, under
  whatever timestamp. That copy, or a file at the very destination, is kept; the rest are copied. An application's own
  migration of the same base name is no copy, so the member's is published beside it and the member's collision guard
  refuses a table both create.
- A tag no provider registered is reported and the run exits 1; the rest is still published.
- The prefix for `laravel-authorization`'s tables comes from `--prefix`, or is asked for interactively, and is written
  only while neither its configuration nor any of its migrations has been published, into the configuration published
  in the run, as the default of `AUTHORIZATION_TABLE_PREFIX`, the member's `tables.prefix` setting. Tables already
  migrated would otherwise lose their names. A prefix is checked with the member's `TableNames::isValidPrefix()`, and
  an invalid one refuses the run with Symfony's `INVALID` exit code before anything is published, rather than leaving a
  file the member refuses at boot. A prefix that can no longer be written is reported as carried when
  `TableNames::prefix()` already reads it, or as not written.
- The install writes no other member configuration: audit-log's `capture.laravel.except_guards` and
  `definitions.require_registered` are owed, and `Checks\AuditCheck` enforces them.
- Every run ends with a short list of what the application still owes, each item linking to the installation guide's
  section on it.

### Scheduling (IAM-2.6)

- `Iam::schedule($schedule)` hands the schedule to `Scheduling\IamSchedule::register()`, which registers `mfa:prune`
  daily, as MFA's lifecycle guide schedules it; SSO's own `Operations\OperationsSchedule::register()`, which schedules
  `sso:prune`, `sso:domains:recheck`, `sso:metadata:refresh` and `sso:keys:expiring` at `sso.operations.cadence.*`
  and registers nothing while SSO is not in use; and, while `audit-log.delivery.mode` is exactly `outbox`, as audit-log
  reads it, `audit-log:drain --until-empty` every minute, as audit-log's README schedules it. `sso:prune` is therefore
  never registered by this package directly, so it runs once.
- Audit-log's own seal, sweep, verify and prune, which audit-log registers on the application's schedule itself, are
  never registered again.
- No task is given a cache mutex: each command is safe on several servers at once, as SSO's operations schedule
  promises for its own, so a stale mutex can never suppress maintenance. Every value is read when the schedule is
  built.

### Platform (IAM-2.8)

- `composer.json` requires `ext-bcmath`, `ext-curl`, `ext-dom`, `ext-hash`, `ext-libxml`, `ext-mbstring`,
  `ext-openssl` and `ext-zlib`: the union of every member's own `ext-*` requirements, which are SSO's set, so Composer
  refuses to install the suite where one is missing. Composer plugins take effect only from the root application's
  `allow-plugins`, which this package cannot declare for it, so allowing SSO's
  `simplesamlphp/composer-xmlprovider-installer` is owed.

### Checks (IAM-10.1 to IAM-10.3, IAM-2.3, IAM-2.5)

- `Console\CheckCommand` (`iam:check`) is thin: it hands its output to `Checks\Checker::run()`, the one core method, and
  exits `0` only when that answers that everything passed. The checker runs the members' own check commands through the
  console, in the publications' working order: `authentication:check`, `authorization:check` (which reports
  `laravel-authorization`'s settings, seams, grant hooks and connection, and exits `1` on a refused setting and `3` on a
  report it could not complete, and is required like the rest), `mfa:check`, `sso:check` and `audit-log:check`. Glue,
  not policy: their checks stay theirs, each prints in its own words, and one that exits non-zero fails the run, so a
  refusal and an incomplete report alike fail it closed. `IamServiceProvider::register()` declares `iam:check` to
  `laravel-authorization` as a command that composes `authorization:check`
  (`Diagnostics\Declarations::composingCommand()`), so when it is the process's command `laravel-authorization` boots
  for diagnosis: a broken authorization setting throws nothing at boot and is reported by `authorization:check`, which
  exits `1` and fails the run. One that throws is its
  member's defect and stops the run with that exception, which fails closed. Every one is required (IAM-1.3): one that
  is not registered fails the run.
- This package's own checks follow, and run only there (IAM-10.3, amended): no member's command reports them. Each is
  behind the internal `Checks\Contracts\Check` contract (`subject()`, `applies()`, `checks()`): each closure throws for
  a problem, returns a note for something worth knowing that is no failure, and returns nothing otherwise; every closure
  runs, so one run reports every problem. Each of this package's checks reads configuration and the container only,
  never a guard's caller, a request or the database (the members' checks read what their own notes say, audit-log's the
  schema of its tables, so `iam:check` runs after `migrate`), and names keys, seams, guards, connections and classes in
  its messages, never a secret or credential (a connection's or a model's name may appear):
  - `StorageCheck` (IAM-2.3): every member key on the shared connection, the shared connection configured in
    `database.connections`, and the model of each user provider a `jwt` or `api_key` guard uses on it, read from the
    model's own connection without a query. A guard naming no provider uses the default one (`auth.defaults.provider`),
    as `laravel-authentication` hands its provider to Laravel, so that provider's model is read for it. No setting names
    the principal models, so they stay with the installation guide (`docs/guides/installation.md`, which `checks.md`
    repeats). Audit-log's storage connection, when another, is a note
    (`audit-mapping.md`).
  - `MandatorySeamsCheck` (IAM-10.2): every row the capabilities declare mandatory now (`SeamBinding::isMandatory()`,
    read again from the configuration and the container as they stand) is bound, and its member does not say it still
    holds the member's default (`SeamBinding::holdsDefault()`); any other binding passes. A row is checked whatever
    this package's capability switch says: with the switch off the application binds the seam, under the same mandate.
    While SSO is in use, the rows of `SsoBridgeCheck::CAPABILITIES` (`SsoSeams`, `TenancySeams`) are left to the
    bridge, so `iam:check` reports each mandatory seam once; while SSO is not in use, the bridge
    does not apply, and they are checked here. The mandates: SSO's session revocation, MFA's session revoker and the
    passkey factor gate always; the external identity links and the linker while SSO is in use; the
    re-authentication sessions, the tenant authentication policy and MFA's active tenant resolver while SSO's
    enforcement is on or a tenant MFA requirement is named or bound; the enforcement inheritance while a tenant tree is
    named or bound and SSO's enforcement is on; `laravel-authentication`'s scope registry while a guard accepts
    `api_key` or `client_credentials`, as the bound application policy says (asked only as the check reads the
    mandate), and its application access while `authorization.application_access` maps an application
    (`Authorization\AccessMandates`).
  - `Sso\SsoBridgeCheck` (IAM-2.5, IAM-10.2): while SSO is in use, read as SSO's `Features::isInUse()` reads it, and
    reported under `sso`: each SSO application's guard allowing `external_provider`, no application's
    `unlinked_handoffs` on, and the mandatory seams of `SsoSeams` and `TenancySeams` (`SsoBridgeCheck::CAPABILITIES`).
    The base URL is SSO's own `EndpointsCheck`'s and the storage connection the storage alignment's.
  - `ContextNamespacesCheck`: the `mfa` namespace has a contributor in every application (MFA is always installed),
    and the `sso` namespace while SSO is in use, so the check always applies; each namespace nobody holds is reported
    on its own, naming the switch (`iam.adapters.mfa` or `iam.adapters.sso`) that registers this package's
    contributor there.
  - `AuditCheck` (IAM-9, IAM-2.5): every `jwt` and `api_key` guard excluded
    (`CaptureExclusions::unexcludedGuards()`), Gate capture off (`laravel-authorization` is always installed) and
    `require_registered` on, the values `iam:install` owes (decision Q5 (a)), whatever the mappers say: with them
    off, whatever maps the members' events still records a sign-in beside audit-log's own capture, and the bullets
    stand unconditionally in IAM-2.5. Only the mappers' registration with audit-log (`AuditRegistrations::REGISTERED`)
    follows their switch.
  - `CrossMemberConfigurationCheck` (IAM-2.5): every MFA application names a guard of the `jwt` driver, the one that
    holds sessions, so one on an `api_key` or `session` guard, which every MFA adapter refuses at runtime
    (`Mfa\CurrentSession`), is refused at deploy instead; every operation MFA names (`Mfa\Enums\Operation`) is declared
    under `authentication.freshness`, or the guard's own block, for each MFA application's guard, and, while SSO is in
    use, every operation SSO names (`FreshnessOperation`) for each SSO application's guard; while SSO's enforcement is
    on or a tenant MFA requirement is named or bound (`TenancySeams::isEnforcedOrRequired()`), or the authorization and
    SSO adapters are both on, so the grant hook reports `laravel-authorization`'s grants to SSO's scope widening
    (`AuthorizationSeams::reportsWidenings()`), or the authorization adapters are on while the application names or
    binds a tenant tree (`AuthorizationSeams::isOn()` and `TenancyContracts::hasTree()`), `laravel-authentication`'s
    `TenantResolver` is no longer its default, as `isPackageDefault()` says, since MFA's tenant requirement, the tree's
    changes and SSO's revocation resolve the session's tenant through it, and the grant hook the tenant of every grant
    that widens (`Tenancy\TenantReferences`), while `laravel-authentication` admits a principal's own tenant without
    one. SSO's own bullets are each held once: the applications' sign-in method and unlinked handoffs by
    `Sso\SsoBridgeCheck`, `sso.endpoints.base_url` by SSO's own `EndpointsCheck` (which `sso:check` runs while SSO is in
    use, refusing more than an unset value), and `sso.storage.connection` by the storage alignment, at boot and in
    `StorageCheck`; audit-log's are `AuditCheck`'s, so nothing is reported twice; `laravel-authorization`'s seams are
    bound through the container, so none of its resolver keys is required to name an adapter. While the application has
    memberships (`TenancyContracts::hasMemberships()`), so its people act in tenants, `laravel-authorization`'s resource
    tenant resolver left on its default is a note, never a failure, as `laravel-authorization` says whether the contract
    still holds its default (`AuthorizationServiceProvider::isPackageDefault()`): a class the application names in
    `authorization.resource_tenant_resolver` it binds as no default, so no key is read. A model declaring its tenancy
    (`QueryableResource`) or naming its tenant (`AuthorizableResource`) needs no resolver, which no check can see, and
    which tenant owns a record is the application's rule (`authorization.md`). A provider attribute beyond SSO's
    standard mapping depends on each connection's mapping, a database row, so it stays with the guides
    (`docs/guides/authentication-and-sso.md`, Mapped attributes, and `checks.md`), as SSO's routes do
    (`docs/guides/example-application.md`).
  - `SchedulesCheck` (IAM-2.6): a note, never a failure, naming each run `IamSchedule` registers (`mfa:prune` and
    `authorization:prune`; `audit-log:drain --until-empty` while delivery is through the outbox) that no event on the
    application's schedule runs, since a run may be started by something no check can see. A schedule that cannot be
    built (a malformed SSO cadence) fails the run with its cause. Audit-log's own schedules are `audit-log:check`'s.
- Boot's refusal of a storage mismatch or a member that has not registered stands aside while `iam:check` runs (it is
  one of `IamServiceProvider`'s unchecked commands), so `StorageCheck` reports a mismatch, and a member that has not
  registered fails the run as its check command is not registered.

### What the authorization glue adds

- Its first part (decision Q8) binds `laravel-authorization`'s seams (`Authorization\AuthorizationSeams`, see
  `authorization.md`): `laravel-authentication`'s scope registry and application access join the mandatory rows
  `MandatorySeamsCheck` reads, under the mandates `Authorization\AccessMandates` declares. `laravel-authorization`'s
  subject resolver, requirement checker and session policy source are bound through the container by this package
  rather than named in its configuration, so `iam:install` writes none of `authorization.subject_resolver`,
  `authorization.requirement_checker` or `authorization.session.source`, `CrossMemberConfigurationCheck` requires none
  of them, and a class the application names there is kept. `authorization:check` already runs inside `iam:check`.
- Its second part aligns `authorization.connection` with the other members' keys (`StorageConnection::MEMBER_KEYS`,
  `ConnectionAlignment`), so boot refuses it naming another connection and `StorageCheck` reports it; registers
  `authorization:prune` daily in `IamSchedule`, which `SchedulesCheck` notes when nothing runs it; and notes a resource
  tenant resolver left on `laravel-authorization`'s default while people act in tenants
  (`CrossMemberConfigurationCheck`). The tenant resolver requirement of `CrossMemberConfigurationCheck` gains the grant
  hook's condition (the authorization and SSO adapters both on, `AuthorizationSeams::reportsWidenings()`) and the tree's
  (the authorization adapters on while the application names or binds a tenant tree, `TenancyContracts::hasTree()`), so
  a widening grant or a tree read never resolves its tenant through `ResolveNoTenant`. No resource tenant resolver is
  named by `iam:install`: a record's tenant is the application's to say, which this package cannot read from its models
  (`authorization.md`). `iam:install` still writes none of `laravel-authorization`'s resolver keys, and
  `authorization:check` already ran inside `iam:check`, where its refusal (exit `1`) and its incomplete report (exit
  `3`) fail the run as any member's non-zero exit does. Its report names each adapter this package bound over one of
  `laravel-authorization`'s contracts as declared by `laravel-iam` (`authorization.md`).

## Success Path

1. A fresh application requires this package and runs `php artisan iam:install`; asked, it prefixes
   `laravel-authorization`'s tables or not.
2. Every member's configuration, language files and migrations, and `config/iam.php`, are published; the run ends
   with what the application still owes, and exits 0.
3. Run again, it publishes nothing and changes no file: every configuration and language file is kept and every
   migration recognised.
4. An application moving from installing the members directly runs it the same way: whatever it published, under any
   timestamp, is recognised and kept, and the rest is published.
5. The application calls `Iam::schedule($schedule)` from `withSchedule()`.
6. On every deploy, `php artisan iam:check` runs every member's check, then this package's, and exits 0 once
   everything holds; a note (a schedule left off, audit-log on its own connection) is reported without failing.

## Failure / Edge Cases

- A tag no provider registered (a member registers its tags only in the console) is reported, the rest is still
  published, and the run exits 1.
- An authorization configuration published in the run that no longer holds the member's defaults (a member reshaped
  it) is written nothing, and the prefix is reported as owed.
- A malformed SSO cadence is SSO's own `InvalidArgumentException`, thrown as the schedule is built, so a scheduler never
  starts with it. `iam:check` reports it as the one `[schedule]` problem only when the schedule is first built inside
  `iam:check`; when the application resolves the schedule while the console bootstraps (the `Schedule` facade in
  `routes/console.php`), the exception stops every console command as it starts, `iam:check`, `config:clear` and
  `migrate` included, with SSO's message and exit code 1, and no report. A delivery mode audit-log does not read as
  `outbox` schedules no drain.
- `authorization:prune` (IAM-2.6) is registered whatever `iam.adapters.authorization` says: `laravel-authorization`'s
  grants expire whether or not this package binds its seams.
- MFA's own boot check (it stands aside only for `mfa:check` and the configuration commands) and
  `laravel-authorization`'s configuration validation in its `boot()` throw before `iam:check` can run, so a
  configuration either refuses stops `iam:check` with that member's message and a non-zero exit: it fails closed,
  though without this package's report.
- A seam is a member's default only when the member says so: an application that binds a member's default class by
  name is refused only by a member whose `isPackageDefault()` counts it (MFA's does).
- An application keeping each tenant's rule to itself while it keeps a tree binds an inheritance class of its own:
  SSO's `OwnTenantInheritance`, bound by the application, is kept and, since SSO does not count it as its default,
  passes the check.
- Gaps in the members that installation and the checks work around:
  - SSO's `OperationsSchedule::register()` throws on a malformed cadence as the schedule is built, while audit-log's
    `IntegritySchedule` never throws from its own, so one malformed SSO cadence stops the application's whole schedule,
    and, whenever the schedule is resolved while the console bootstraps (the `Schedule` facade in `routes/console.php`),
    every console command, `iam:check`, `sso:check` and `config:clear` included, so a cached cadence cannot even be
    cleared from the console. This package leaves SSO's exception as it is, rather than catching it in `IamSchedule`,
    which would drop the rest of SSO's operations from the schedule without a word, a policy that is SSO's to choose;
    one rule for the suite (skip a malformed task and leave the member's check to report it, as audit-log does, or
    refuse) would settle which.
  - MFA's boot check stands aside for `mfa:check` and the configuration commands only, and `laravel-authorization`
    validates its configuration in `boot()` for every command, so a configuration either refuses stops `iam:check`
    before it reports; standing aside for a composing package's check command too would let `iam:check` report it.
  - `laravel-authorization`'s prefix rule lives in its `@internal` `TableConfigValidator`, so `InstallCommand` repeats
    it; a public check of a prefix would let it ask the member.
  - No member publishes its migrations through `publishesMigrations()`, and `vendor:publish` compares only a whole file
    name, so recognising a migration by its base name lives in `MigrationLedger`. That is no member's defect: a member
    that moves to `publishesMigrations()`, which renames each file with the time it is published, is still recognised.

## Implementation Anchors

- `src/Console/InstallCommand.php`: `handle()`, `tablePrefix()`, `prefixTables()`, `prefixableConfiguration()`.
- `src/Install/MigrationLedger.php`: `baseName()`, `copyOf()`.
- `src/Scheduling/IamSchedule.php`: `register()`; `src/IamManager.php`: `schedule()`.
- `src/Console/CheckCommand.php`: `handle()`; `src/Checks/Checker.php`: `run()`, `MEMBER_COMMANDS`, `CHECKS`;
  `src/Checks/Contracts/Check.php`.
- `src/Checks/StorageCheck.php`, `src/Checks/MandatorySeamsCheck.php` (`checksFor()`, `assertBound()`),
  `src/Bindings/SeamBinding.php` (`holdsDefault()`), `src/Checks/Sso/SsoBridgeCheck.php` (`CAPABILITIES`),
  `src/Checks/ContextNamespacesCheck.php`, `src/Checks/AuditCheck.php`, `src/Checks/CrossMemberConfigurationCheck.php`,
  `src/Checks/SchedulesCheck.php`.
- The mandates: `src/Sso/SsoSeams.php` (`isInUse()`), `src/Mfa/ContextSeams.php`, `src/Tenancy/TenancySeams.php`
  (`isEnforcedOrRequired()`); `src/IamServiceProvider.php`: `seamProviders()`, `UNCHECKED_COMMANDS`,
  `registerConsole()`.
- `composer.json`: `require`.

## Authoritative Tests

- `tests/Feature/Console/InstallCommandTest.php` `testEveryMembersFilesArePublished`,
  `testRunningTwiceChangesNothing`, `testAMigrationPublishedUnderAnotherTimestampIsRecognised`,
  `testAnApplicationsMigrationSharingABaseNameIsNotTakenForTheMembers`, `testAFileAtAMigrationsPathIsNeverOverwritten`,
  `testTheRunEndsWithWhatTheApplicationStillOwes`, `testATagNoProviderRegisteredFailsTheRun`,
  `testThePrefixOptionPrefixesTheAuthorizationTables`, `testAValidPrefixIsWritten`,
  `testRunningAgainWithAPrefixWritesNothing`, `testAPrefixIsNotWrittenOnceAnAuthorizationMigrationIsPublished`,
  `testAReshapedAuthorizationConfigurationIsOwedThePrefix`, `testAnInvalidPrefixRefusesTheRunWithNothingPublished`,
  `testInteractiveTheRunAsksForThePrefix`
- `tests/Unit/Install/MigrationLedgerTest.php` `testTheBaseNameDropsTheTimestampAndTheExtension`,
  `testACopyUnderAnotherTimestampIsRecognised`, `testAnApplicationsMigrationOfTheSameBaseNameIsNoCopy`,
  `testOnlyTheDirectorysOwnPhpFilesAreRead`
- `tests/Integration/Install/PrefixedAuthorizationTablesTest.php` `testTheLongestPrefixMigratesEveryTable` (MySQL and
  PostgreSQL)
- `tests/Feature/Scheduling/IamScheduleTest.php` `testOnlyThePrunesAreScheduledWhileSsoIsNotInUseAndDeliveryIsSync`,
  `testSsosOperationsAreScheduledOnceWhileSsoIsInUse`,
  `testTheDrainIsScheduledEveryMinuteWhileDeliveryIsThroughTheOutbox`,
  `testAnyOtherDeliveryModeSchedulesNoDrain`, `testAuditLogsOwnSchedulesAreNeverRegisteredAgain`
- `tests/Feature/Console/CheckCommandTest.php` `testAConfiguredApplicationPasses`,
  `testMfasDefaultLeftOnAMandatorySeamFailsTheRun`, `testAMembersFailureFailsTheRun`,
  `testAStorageMismatchIsReportedRatherThanRefusedAtBoot`,
  `testABrokenAuthorizationSettingIsReportedRatherThanRefusedAtBoot`, `testAMemberThatNeverRegisteredFailsTheRun`,
  `testSsosSideIsChecked`
- `tests/Unit/Checks/CheckerTest.php` `testEveryCheckRunsAndTheRunPasses`, `testAMemberCommandFailingFailsTheRun`,
  `testAMemberCommandThrowingStopsTheRun`, `testAMissingMemberCommandFailsTheRun`,
  `testEachCheckIsReported`
- `tests/Feature/Checks/MandatorySeamsCheckTest.php` `testTheMembersDefaultsFail`, `testAResolvedMembersDefaultFails`,
  `testTheApplicationsOwnBindingPasses`, `testMfasRegisteredDefaultFails`, `testAnUnboundMandatorySeamFails`,
  `testTheSeamsSsosCheckHoldsAreLeftToIt`, `testTheLinksAreMandatoryWhileSsoIsInUse`,
  `testTheTenantSeamsAreMandatoryWhileATenantsRuleIsOn`, `testTheInheritanceIsMandatoryWhileEnforcingOverATree`
- `tests/Feature/IamServiceProviderTest.php` `testTheCommandsAreRegisteredInTheConsole`,
  `testEveryCapabilitysSeamsAreProvided`
- `tests/Feature/Checks/StorageCheckTest.php` `testAMemberKeyOnAnotherConnectionFails`,
  `testEveryIdentityModelMustLiveOnTheSharedConnection`,
  `testAGuardNamingNoProviderReadsTheDefaultProvidersModel`, `testAuditLogOnAnotherConnectionIsNoted`
- `tests/Feature/Checks/ContextNamespacesCheckTest.php` `testItRequiresSsoOnlyWhileSsoIsInUse`,
  `testANamespaceNobodyRegisteredFails`, `testAnMfaNamespaceNobodyRegisteredFails`
- `tests/Feature/Checks/AuditCheckTest.php` `testAuditLogAsItShipsFails`, `testTheOwedValuesPass`,
  `testWithTheMappersOffAuditLogsValuesAreStillEnforced`, `testGateCaptureOnFails`
- `tests/Feature/Checks/CrossMemberConfigurationCheckTest.php` `testMfasOperationsMustBeDeclared`,
  `testEveryMfaApplicationMustBeAGuard`, `testEveryMfaApplicationMustBeAJwtGuard`,
  `testSsosOperationsMustBeDeclaredWhileSsoIsInUse`,
  `testSsosBulletsAreHeldBySsosCheck`, `testAuditLogsBulletsAreHeldByTheAuditCheck`,
  `testTheTenantResolverMustResolveWhileATenantsRuleReachesASession`, `testGrantsNeedNoResolverWhileSsoIsOff`,
  `testNoTenantsRuleRequiresNoResolver`,
  `testTheResourceTenantResolverIsNotedWhilePeopleActInTenants`,
  `testAResourceTenantResolverTheApplicationNamesIsNotNoted`
- `tests/Feature/Checks/SchedulesCheckTest.php` `testThePrunesAreNotedUntilThePackageSchedulesThem`,
  `testTheDrainIsNotedWhileTheOutboxIsOn`, `testAScheduleThatCannotBeBuiltIsAProblem`
- `tests/Feature/Checks/Sso/SsoBridgeCheckTest.php` `testItAppliesOnlyWhileSsoIsInUse`, `testEachApplicationIsChecked`,
  `testTheBaseUrlAndTheStorageConnectionAreLeftToTheirOwners`, `testTheMandatorySeamsAreChecked`

## Change Triggers

- A member adding, renaming or removing a publishing tag or its namespace: `InstallCommand`'s tags follow.
- `laravel-authorization` renaming `AUTHORIZATION_TABLE_PREFIX` or changing its prefix rule: `InstallCommand`'s check
  and the default it writes follow.
- A member scheduling work of its own, or leaving more to the application: `IamSchedule` and `SchedulesCheck`
  follow.
- A member adding a PHP extension or a Composer plugin: `composer.json` follows.
- A member adding a check command, a check of its own that covers one of this package's (glue, not policy), or a
  public way to add a check: `Checker` and the checks follow.
- A member renaming a mandatory seam's default, a mandate changing (`AccessMandates`' application access and scope
  registry among them), or
  MFA or `laravel-authorization` standing their boot validation aside for `iam:check`: `MandatorySeamsCheck`,
  `ContextNamespacesCheck` and `CheckCommand` follow.
- SSO changing `Features::isInUse()` or the meaning of `FreshnessOperation`: `SsoBridgeCheck`, `SsoSeams::isInUse()`
  and `CrossMemberConfigurationCheck` follow.
- `laravel-authorization` binding its resource tenant resolver so the configured class can be read from its binding:
  `CrossMemberConfigurationCheck` follows. `authorization:check` exiting `0` on a refusal or an incomplete report, or
  throwing out of the console kernel's `call()` rather than ending with its exit code: `Checker` follows.
- A member closes one of the gaps listed above: the workaround it names goes.
