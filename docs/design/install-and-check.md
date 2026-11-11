# Install and Check

## Purpose

This note describes how `iam:install` publishes every member's files and this package's configuration into an
application, recognising what is already there, and writes the few member values this package needs (IAM-2.1, IAM-2.4,
IAM-2.5); how `Iam::schedule()` registers the members' scheduled work they leave to the application (IAM-2.6); the PHP
extensions this package declares (IAM-2.8); how `iam:check` runs every member's check and this package's own
(IAM-10); what `laravel-authorization`'s glue adds to both; and the gaps in the members it works around.

## Invariants

### Installation (IAM-2.1, IAM-2.4)

- `Console\InstallCommand` (`iam:install`) is thin: it reads `--prefix`, or asks for the prefix while it can still be
  written and the command is interactive, hands it to `Install\Installer::install()`, the one core method, and prints
  the `Install\InstallReport` it returns. With `--no-interaction` it asks nothing and prefixes nothing unless `--prefix`
  says so; an empty `--prefix` is no prefix, and nothing is asked.
- `Install\Publications::all()` is the working order: member by member, `laravel-authentication`,
  `laravel-authorization`, `laravel-mfa`, `laravel-sso`, `laravel-audit-log`, then this package's `iam-config` last;
  within a member, its `-config`, `-lang` and `-migrations` tags (`laravel-authentication` ships no language files).
  No member's migration has a foreign key to another's, so the order only makes each run read the same.
- Every file is published from the paths its own provider registers under the tag
  (`ServiceProvider::pathsToPublish(null, $tag)`), to the destination the provider gives it, so the member, never this
  package, decides where its files go. A tag that publishes a directory (MFA's and `laravel-authorization`'s
  migrations, every language tag) is expanded to its files, in name order, so each file is judged on its own: Laravel's
  `vendor:publish` compares only a whole file name.
- Nothing is ever overwritten, and nothing the run did not publish is changed:
  - a configuration file or a language file already at its destination is kept as it is;
  - a member's migration is recognised by its base name, its file name without the `YYYY_MM_DD_HHMMSS_` timestamp and
    the extension (`Install\MigrationLedger::baseName()`), among the `.php` files directly in the directory it would
    be published to, read once per run; a file of that base name counts as the member's copy only while it names the
    member's namespace (`Publication::$namespace`), as every member's migration does, and a copy found is reported and
    never published again.
- Where a migration's identity is in doubt the run fails closed, as incomplete (exit 1), rather than report success; the
  report names each as a `[conflict]` (`InstallReport::$conflicts`):
  - a migration of the application's own that shares a member's base name (`create_roles_table`,
    `create_permissions_table`, `create_policies_table`, `create_rate_limits_table`) is not taken for the member's: the
    member's is published beside it, so its table is never left uncreated without a word, and the run that finds it
    fails, naming both, for the application to check the two create no table in common before it migrates (the
    member's collision guard refuses one both create). A later run recognises the member's copy and passes. A
    namesake of one of `laravel-authorization`'s migrations is no conflict in a run that writes the prefix into the
    configuration it publishes (decision recorded here, IAM-2.4): every table name the member derives then carries the
    prefix, so the two create different tables, and the run reports it as a `[note]` (`InstallReport::$notes`) rather
    than failing; it stays a conflict when the prefix is not written, and a namesake of another member's migration is
    a conflict whatever the prefix;
  - a file of the application's at the very path a member's migration is published to is kept, the member's migration
    is not published, and every run fails until the application moves it.
- Audit-log's values (decision Q5 (a), IAM-2.5) are written only into `config/audit-log.php` published in the same run,
  as soon as it is published and before the next file is copied (`Install\AuditLogConfiguration::write()`):
  `capture.laravel.except_guards` gets the list `Audit\CaptureExclusions::exceptGuards()` computes (every `jwt` and
  `api_key` guard, after whatever the configuration already excludes), and `definitions.require_registered` becomes the
  default of the `env()` call the file reads, so `AUDIT_LOG_DEFINITIONS_REQUIRE_REGISTERED` still wins. Gate capture
  already defaults off in the published file, so nothing is written for it. Each value is written only where the file
  still holds audit-log's own default, matched exactly once. A configuration file the application published before is
  never written: each value it does not hold, read from the configuration in force, is reported as owed, as Gate capture
  switched on is.
- The prefix for `laravel-authorization`'s tables (IAM-2.4) is offered, and written, only while neither its
  configuration file nor any of its migrations, under any timestamp, has been published, so no table has a name yet
  (`Installer::offersTablePrefix()`). It is written into the configuration file published in the run, as soon as it is
  published and before any of `laravel-authorization`'s migrations is copied, as the default of each
  `AUTHORIZATION_TABLE_*` variable (`Install\AuthorizationTablePrefix::apply()`), so the variable still wins and
  `laravel-authorization`'s migrations and models read the prefixed names from the first migration on. A prefix is
  lower-case letters, digits and underscores, starting with a letter, at most 16 characters: the longest name the
  migrations derive from a table name (a foreign key's) is 46 characters before the prefix, so every one stays within
  PostgreSQL's 63 and MySQL's 64. A prefix given when it cannot be written is reported as owed, unless the configuration
  published before already carries it on every table name it defaults to, each the name the prefix gives the table:
  the prefix followed by the name `laravel-authorization` ships for it, read from the installed package's own
  configuration, or that name alone where it already starts with the prefix (`AuthorizationTablePrefix::carries()`), as
  a run with the same prefix leaves it, since `apply()` never prefixes a name twice: running `--prefix` again is
  then noted, never owed. A prefix that is only the start of the one written (`iam` after `iam_`) is not carried, since
  the tables are not named with it, so it is owed.
- Everything the run reads from the configuration (the exclusions, whether the prefix can be written) and the prefix
  itself are judged before any file is published, so a malformed `except_guards` or an invalid prefix refuses the run
  with Symfony's `INVALID` exit code and nothing changed.
- Every run ends with what the application still owes (`Installer::OWED`): migrating, naming the connection each
  member's tables are created on (`laravel-authentication`'s, MFA's, SSO's and `laravel-authorization`'s on
  `iam.storage.connection`, which the storage alignment shares; audit-log's on `audit-log.storage.connection`, which it
  never writes, the default connection when unset); its email and SMS
  gateways; its memberships and tenant tree, and laravel-mfa's `TenantRequirement`; `laravel-authentication`'s
  `TenantResolver`, before MFA's tenant requirement is bound or SSO's enforcement turned on, since the tenant policy,
  the tree's changes and SSO's revocation resolve the session's tenant through it while `laravel-authentication` admits a
  principal's own tenant without one, so an application that never needed a resolver needs one then; its provisioner;
  the routes, following this package's example application guide, so SSO's handoffs are redeemed through
  `Iam::signIns()`, `Iam::reauthentications()` and `Iam::links()`, never `HandoffRedemption` directly (the adapters
  answer only a redemption or a caller those core methods recorded, and `iam:check` cannot see a route);
  `Iam::schedule()`; a queue worker for `laravel-authentication`'s delivery of one-time codes
  (`authentication.delivery.queue.*`), which MFA's email and SMS codes go through once the gateways are named, whether
  or not SSO is in use, and for SSO's metadata refresh while it is; allowing SSO's Composer plugin in its own
  `composer.json`; mapping each application to the permission to use it (`authorization.application_access`), since
  `laravel-authentication`'s application access is answered from `laravel-authorization` and admits anyone to an
  application the map does not name, and binding its tenant access where principals act beyond their own tenant
  (IAM-2.1);
  declaring MFA's and SSO's freshness operations for their applications' guards, and allowing `external_provider` on
  each SSO application's guard, which `iam:check` refuses but the install cannot write; keeping every guard it adds
  excluded; defining every audit code the application records itself, which `definitions.require_registered` otherwise
  refuses; and `iam:check` on every deploy.

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
- This package's own checks follow, each behind the internal `Checks\Contracts\Check` contract, which mirrors SSO's
  `ConfigurationCheck` (`applies()`, `checks()`, plus the `subject()` it is reported under): each closure throws for a
  problem, returns a note for something worth knowing that is no failure, and returns nothing otherwise; every closure
  runs, so one run reports every problem. Each of this package's checks reads configuration and the container only,
  never a guard's caller, a request or the database (the members' checks read what their own notes say, audit-log's the
  schema of its tables, so `iam:check` runs after `migrate`), and names keys, seams, guards, connections and classes in
  its messages, never a secret or credential (a connection's or a model's name may appear):
  - `StorageCheck` (IAM-2.3): every member whose storage key the alignment reads (`laravel-authentication`, MFA and
    SSO) registered, every member key on the shared connection, the shared connection configured in
    `database.connections`, and the model of each user provider a `jwt` or `api_key` guard uses on it, read from the
    model's own connection without a query. A guard naming no provider uses the default one (`auth.defaults.provider`),
    as `laravel-authentication` hands its provider to Laravel, so that provider's model is read for it. No setting names
    the principal models, so they stay with the installation guide (`docs/guides/installation.md`, which `checks.md`
    repeats). Audit-log's storage connection, when another, is a note
    (`audit-mapping.md`).
  - `MandatorySeamsCheck` (IAM-10.2): every row the capabilities declare mandatory now (`SeamBinding::isMandatory()`,
    read again from the configuration and the container as they stand) is bound, and its live binding (`Checks\SeamHolders`,
    never building anything new) names neither one of the row's member defaults nor any other class of a member's own,
    the row's adapter apart (SSO's own `LinkStore` is the linker's) and the member classes the row accepts
    (`SeamBinding::$accepted`): SSO's `LinkStore` on the link storage, which SSO's guide binds it to, is SSO's real
    store, not a permissive default, so it is accepted there (decision recorded here). A row is checked whatever this
    package's capability switch says, as the tenant policy's note has it: with the switch off the application binds the
    seam, under the same mandate. The binding rule's outcome adds a note for each seam it kept with the application's
    binding. A binding whose implementation cannot be read without building it (a closure of the application's own,
    which `SeamHolders` names nothing for: the class declaring a closure does not tell what it returns) fails too, since
    the check takes nothing on trust; the application binds a mandatory seam by class name or as an instance, or the
    shared instance something has already resolved is read. An anonymous class is judged by what it is, not by its
    debug name, which starts with the contract it implements and so would read the application's implementation of a
    member's contract as the member's own (decision recorded here): one extending a class is named by that class, whose
    behaviour it inherits, so an anonymous subclass of a member's default still fails; one extending nothing is the
    application's own, named by the file and line it is declared at, and passes. No member declares an anonymous
    default, so where the class is declared is not read. While SSO is in use, the rows of
    `SsoBridgeCheck::CAPABILITIES` (`SsoSeams`, `TenancySeams`) are left to the bridge, which `sso:check` or
    `SsoBridgeFallbackCheck` runs, so `iam:check` reports each mandatory seam once; while SSO is not in use, the bridge
    does not apply, and they are checked here. The mandates: SSO's session revocation, MFA's session revoker and the
    passkey factor gate always; the external identity links, the linker and the link storage while SSO is in use; the
    re-authentication sessions, the tenant authentication policy and MFA's active tenant resolver while SSO's
    enforcement is on or MFA's tenant requirement is bound; the enforcement inheritance while a tenant tree is
    named or bound and SSO's enforcement is on; `laravel-authentication`'s scope registry while a guard accepts
    `api_key` or `client_credentials`, as the bound application policy says (asked only as the check reads the
    mandate), and its application access while `authorization.application_access` maps an application
    (`Authorization\AccessMandates`).
  - `SsoBridgeFallbackCheck` (IAM-2.5, IAM-10.2): while SSO is in use and `sso:check` does not run the bridge
    (`SsoCheckRegistration::isInForce()` is false: the application keeps a check of its own under `iam`, which the
    registration leaves in place, binds a checker of its own, SSO's class built from a list of its own included, or
    SSO's checks are unbound), every one of the bridge's checks, reported under `sso`: each SSO application's guard
    allowing `external_provider`, no application's `unlinked_handoffs` on, and the bridge's mandatory seams. While the
    bridge is in force, or SSO is not in use, it does not apply, so each bullet is checked exactly once. Whether the
    bridge is in force is read from the live checker, resolved as `sso:check` resolves it: it is SSO's own class and
    holds the bridge under `iam` among the checks it was built with, which SSO keeps to itself and which are read from
    its properties as `get_mangled_object_vars()` lists them. The binding's holder and SSO's registry are not enough,
    since an instance, a closure or an `extend()` of the application's can build SSO's class from a list without the
    bridge. It fails closed: a checker that cannot be resolved, or whose checks cannot be read, is taken as not running
    the bridge, so it runs here.
  - `ContextNamespacesCheck`: the `mfa` namespace has a contributor in every application (MFA is always installed),
    and the `sso` namespace while SSO is in use, so the check always applies; each namespace nobody holds is reported
    on its own, naming the switch (`iam.adapters.mfa` or `iam.adapters.sso`) that registers this package's
    contributor there.
  - `AuditCheck` (IAM-9, IAM-2.5): `OperationalAlerts::validate()`, every `jwt` and `api_key` guard excluded
    (`CaptureExclusions::unexcludedGuards()`), Gate capture off (`laravel-authorization` is always installed) and
    `require_registered` on, the values `iam:install` writes (decision Q5 (a)), whatever the mappers say: with them
    off, whatever maps the members' events still records a sign-in beside audit-log's own capture, and the bullets
    stand unconditionally in IAM-2.5. Audit-log's provider registered, whatever the mappers say: boot refuses an
    application without it but stands aside for `iam:check`, so this is the one way `iam:check` meets this package's
    part unregistered (a provider of this package's registered after boot fails its boot instead), and it is reported
    as audit-log's provider missing, never as a late registration; `laravel-authorization`'s registration is reported
    through its check command. Only the mappers' registration with a registered audit-log
    (`AuditRegistrations::REGISTERED`) follows their switch.
  - `SendersCheck`: the routes name channels; every code sign-in method a `jwt` guard allows has its identifier type
    routed to a channel while `laravel-authentication`'s sender is this package's or unbound, since a code of a type
    the routes leave out can be delivered by no gateway and `authentication:check` sees a sender bound and passes; a
    gateway named where none is bound implements its contract, judged by
    its class, never built; and a channel has a gateway while something sends on it through this package, a `jwt`
    guard allowing `email_code` or `phone_code` routed to it, or an MFA application enabling `sms` or `email`, while
    the member's sender is this package's, the member's null default or unbound.
  - `CrossMemberConfigurationCheck` (IAM-2.5): every MFA application names a guard of the `jwt` driver, the one that
    holds sessions, so one on an `api_key` or `session` guard, which every MFA adapter refuses at runtime
    (`Mfa\CurrentSession`), is refused at deploy instead; every operation MFA names (`Mfa\Enums\Operation`) is declared
    under `authentication.freshness`, or the guard's own block, for each MFA application's guard, and, while SSO is in
    use, every operation SSO names (`FreshnessOperation`) for each SSO application's guard; while SSO's enforcement is
    on or MFA's tenant requirement is bound (`TenancySeams::isEnforcedOrRequired()`), or the authorization and
    SSO adapters are both on, so the grant hook reports `laravel-authorization`'s grants to SSO's scope widening
    (`AuthorizationSeams::reportsWidenings()`), or the authorization adapters are on while the application names or
    binds a tenant tree (`AuthorizationSeams::isOn()` and `TenancyContracts::hasTree()`), since `TenantTreeAdapter`
    resolves every tenant `laravel-authorization` asks about through it, `laravel-authentication`'s `TenantResolver` is
    no longer its `ResolveNoTenant`, read through `SeamHolders` without building it, since MFA's tenant requirement, the
    tree's changes and SSO's revocation resolve the session's tenant through it, the grant hook the tenant of every
    grant that widens and the tree adapter every tenant it is asked about (`Tenancy\TenantReferences`), while
    `laravel-authentication` admits a principal's own tenant without one (a resolver bound through a closure cannot be
    read, so it passes). SSO's own bullets are each held once: the applications' sign-in method and unlinked handoffs by
    `Sso\SsoBridgeCheck` (or `SsoBridgeFallbackCheck` while SSO's check does not run it), `sso.endpoints.base_url` by
    SSO's own `EndpointsCheck` (which `sso:check` runs while SSO is in use, refusing more than an unset value), and
    `sso.storage.connection` by the storage alignment, at boot and in `StorageCheck`; audit-log's are `AuditCheck`'s, so
    nothing is reported twice; `laravel-authorization`'s seams are bound through the container, so none of its resolver
    keys is required to name an adapter. While the application has memberships (`TenancyContracts::hasMemberships()`),
    so its people act in tenants, `laravel-authorization`'s resource tenant resolver left on its default is a note,
    never a failure, as `laravel-authorization` says whether the contract still holds its default
    (`AuthorizationServiceProvider::isPackageDefault()`, asked through `MemberDefaults::holdsDefault()`): a class the
    application names in `authorization.resource_tenant_resolver` it binds as no default, so no key is read. A model
    declaring its tenancy (`QueryableResource`) or naming its tenant (`AuthorizableResource`) needs no resolver, which
    no check can see, and which tenant owns a record is the application's rule (`authorization.md`). A provider
    attribute beyond SSO's standard mapping depends on each connection's mapping, a database row, so it stays with the
    guides (`docs/guides/authentication-and-sso.md`, Mapped attributes, and `checks.md`), as SSO's routes do
    (`docs/guides/example-application.md`).
  - `PlatformCheck` (IAM-2.8): every extension `composer.json` declares is loaded in the PHP running the check, and
    SSO's Composer plugin is installed with the registry of every installed `simplesamlphp-xmlprovider` package linked
    into its directory, compared by content. It fails closed: a provider Composer lists without an install path, without
    a readable registry, or whose registry cannot be digested is refused, never passed as having nothing to link.
  - `SchedulesCheck` (IAM-2.6): notes, never failures, for a run left off the schedule, since a run may be started by
    something no check can see. The one failure is a schedule that cannot be built at all: `Iam::schedule()`, hooked
    into the schedule's resolution by the application's `withSchedule()`, registers SSO's operations, which throw on a
    malformed cadence as the schedule is built, and the scheduler would not start either. The schedule is built once,
    by the check's first closure, and that failure is reported as one problem naming the cause, but only when the
    schedule is first built inside `iam:check`. Where it is resolved while the console bootstraps (Laravel's
    `Schedule` facade used from `routes/console.php`, which the console kernel loads before any command runs), the
    `withSchedule()` callback runs as the console starts, SSO's exception stops every console command, `iam:check`
    included, before any check runs, and the command exits 1 with SSO's message and no report (see the gaps below).
    Where it is reported, the container keeps
    the schedule as it stood when the building threw, so no run is then noted missing from it, nor is a call to
    `Iam::schedule()` the application already makes asked for. The notes:
    audit-log's sealing, sweep and verification with no event on the application's schedule running them (switched
    off with nothing else running them), and each run `IamSchedule` registers (`mfa:prune` and `authorization:prune`;
    `sso:prune` while SSO is in use; `audit-log:drain --until-empty` while delivery is through the outbox) missing
    from it. Each of those is noted with the call to `Iam::schedule()`, except `sso:prune` with
    `sso.operations.cadence.prune` switched off (`null` or empty, read as SSO's `OperationsSettings::cadence()` reads
    it): SSO's operations schedule then hands the command to the application, so the note gives that cause (set the
    cadence, or schedule `sso:prune` itself), and a second call to `Iam::schedule()`, which would change nothing and
    duplicate the rest, is never asked for.
    Audit-log's prune is noted the same way, naming `audit-log.retention.schedule`, but only while its retention can
    delete entries, as audit-log's own `Console\IntegritySchedule::prunes()` judges it (audit-log schedules the prune
    only then, and its own check notes no prune switched off): a configured retention keeping anything for a number of
    days, or a bound retention policy other than the configured one. Where audit-log cannot judge it (a malformed
    retention setting, or a bound policy that cannot be resolved), the prune missing from the schedule is noted with
    that cause, by the exception's class and never its message, rather than failing the check.
- Boot's refusal of a storage mismatch or a member that has not registered stands aside while `iam:check` runs (it is
  one of `IamServiceProvider`'s unchecked commands), so `StorageCheck` reports either instead.
- `Checks\SsoCheckRegistration` adds `Checks\Sso\SsoBridgeCheck` to SSO's own checks under the subject `iam`, through
  SSO's registration point (`Config\ConfigurationChecks::add()`, IAM-13.12), never by rebinding SSO's checker, which
  stays SSO's own. The addition is queued from this package's `register()` as a `booted()` callback, so it is made once
  every provider has booted, and, from a `beforeResolving()` callback on SSO's checker, made again just before the
  checker is built once the application has booted. The `booted()` callback lands before SSO's boot check (queued as a
  `booted()` callback from SSO's `boot()` outside the console) whenever this package's provider registers before SSO's
  boots; where it does not (this package's provider registered from another provider's `boot()` after SSO's has booted,
  which queues SSO's boot check first, or SSO's registered once the application has booted, when the callback finds no
  checks of SSO's to add to), the second addition lands as SSO's boot check, a worker command or `sso:check` resolves
  the checker, so each finds the check in every provider order. A resolution before boot adds nothing, and neither
  addition adds to a subject already taken. It is made that late, rather than as SSO's checks are first resolved,
  because Laravel registers the application's providers after the packages': a check the application registers under
  `iam` itself, as SSO recommends (`callAfterResolving()` from its provider's `register()`, or from its `boot()`), lands
  first, and is kept, as an application's binding is (IAM-8.4), where an earlier addition of this package's would make
  SSO refuse the application's with a `LogicException` as SSO's checks are first resolved (decision recorded here).
  `iam:check` then runs the bridge through `SsoBridgeFallbackCheck`. Nothing is added while SSO's provider has not
  registered. SSO runs it after its own checks at boot, as each worker command starts and in `sso:check`, which reports
  it as `[iam]` (IAM-10.3). It applies only while SSO is in use, read as SSO's `Features::isInUse()` reads it, so it
  fails SSO's boot only then (decision Q12), and checks every SSO application's guard allowing `external_provider`, no
  application's `unlinked_handoffs` on, and the mandatory seams of `SsoSeams` and `TenancySeams`
  (`SsoBridgeCheck::CAPABILITIES`). The base URL is SSO's own `EndpointsCheck`'s and the storage connection the storage
  alignment's, which refuses boot on a mismatch already, so the bridge repeats neither. SSO's freshness operations are
  left to `iam:check`, so an application that has not declared them yet is told at deploy rather than refused at boot.
- `Checks\AuthenticationConfigurationCheck` reports this package's checks of `laravel-authentication`'s side in
  `authentication:check` too (IAM-10.3), through `laravel-authentication`'s registration point
  (`Console\ConfigurationChecks::register()`), so the command run at deploy on its own reports them. It copies no
  check: each check with a side of `laravel-authentication`'s implements `Checks\Contracts\AuthenticationCheck`, which
  hands over the closures of its own `checks()` that concern it, about no one guard (`authenticationChecks()`) and about
  a guard by name (`guardChecks()`). They are `StorageCheck`'s identity model of each guard; `MandatorySeamsCheck`'s
  seams that are `laravel-authentication`'s own contracts, and the notes of those the binding rule kept, the seams the
  SSO bridge holds left to it while SSO is in use; every namespace `ContextNamespacesCheck` requires; and
  `CrossMemberConfigurationCheck`'s tenant resolver, and the MFA and SSO applications named after each guard. The
  members' storage keys and the shared connection stay `iam:check`'s alone, as does an MFA or SSO application naming no
  guard `authentication:check` checks (a `session` guard, or none). The adapter asks for the guards
  `authentication:check` checks (those named with `--guard`, otherwise every `jwt` and `api_key` guard), so `--guard`
  limits it, and grades each closure as `Checker` does: one that throws is an error, its message prefixed
  `[iam:<subject>]`, and a note a warning. A check that cannot be resolved, or whose closures cannot be built, is an
  error naming its class and the exception's class, never its message (which `laravel-authentication` asks of a
  registered check), and the checks after it still run. It is registered from `IamServiceProvider::boot()` through
  `callAfterResolving()` on `laravel-authentication`'s checks, which registers it on every instance built and never
  where `laravel-authentication` offers no registration point; `register()` keeps one of each, so it is registered
  once. `Checker::run()` binds `Checker::RUNNING` to `true` while it runs the members' commands, and to `false` once
  they have, thrown or not, and the adapter answers nothing while it is `true`, so `iam:check` reports each problem
  once, under `iam` (decision recorded here).

### What the authorization glue adds

- Its first part (decision Q8) binds `laravel-authorization`'s seams (`Authorization\AuthorizationSeams`, see
  `authorization.md`): `laravel-authentication`'s scope registry and application access join the mandatory rows
  `MandatorySeamsCheck` reads, under the mandates `Authorization\AccessMandates` declares. `laravel-authorization`'s
  subject resolver, requirement checker and session policy source are bound through the container by the binding rule
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
  `3`) fail the run as any member's non-zero exit does. Its report names each adapter the binding rule bound over one of
  `laravel-authorization`'s contracts as declared by `laravel-iam` (`authorization.md`).

## Success Path

1. A fresh application requires this package and runs `php artisan iam:install`; asked, it prefixes
   `laravel-authorization`'s tables or not.
2. Every member's configuration, language files and 50 migrations, and `config/iam.php`, are published;
   `config/audit-log.php` excludes the application's `jwt` and `api_key` guards and refuses unregistered codes; the run
   ends with what the application still owes, and exits 0.
3. Run again, it publishes nothing and changes no file: every configuration and language file is kept and every
   migration recognised.
4. An application moving from installing the members directly runs it the same way: whatever it published, under any
   timestamp, is recognised and kept, the rest is published, and each audit-log value its own `config/audit-log.php`
   does not hold is owed.
5. The application calls `Iam::schedule($schedule)` from `withSchedule()`.
6. On every deploy, `php artisan iam:check` runs every member's check, then this package's, and exits 0 once
   everything holds; a note (a schedule left off, audit-log on its own connection) is reported without failing.

## Failure / Edge Cases

- A tag no provider registered (a member registers its tags only in the console) is reported as `[missing]`, the rest
  is still published, and the run exits 1.
- A migration whose identity is in doubt, an application's own of a member's base name or a file at a member
  migration's very path, is reported as a `[conflict]` and the run exits 1 (see Installation); a namesake of one of
  `laravel-authorization`'s migrations in a run that writes the prefix is a `[note]` instead.
- A file that cannot be copied stops the run with `Exceptions\PublicationFailedException`, naming the path; what was
  published before it is kept, and running again publishes the rest and nothing twice. Since each configuration's values
  are written as soon as it is published, a configuration the stopped run published already holds them: the run after it
  keeps the file as the application's, and finds the audit-log values held and the prefix carried, so it owes neither,
  as a run that never stopped would. Creating its directory or copying it raises a warning, which Laravel's error
  handler would raise as an `\ErrorException` in place of the publication's exception: the installer catches the warning
  with an error handler of the copy's own, restored once the copy returns, and throws the publication's exception with
  the warning as its cause, whatever the application reports.
- An audit-log or authorization configuration published in the run that no longer holds the member's own default (a
  member reshaped it) is written nothing; the value, or the prefix, is owed.
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
- A member that renames a default, or moves a closure binding to another class of its own, is still caught as a member
  default by its namespace; a binding that names no class (a closure of the application's own, or one declared
  outside any class) fails, as its implementation cannot be read without building it.
- An application keeping each tenant's rule to itself while it keeps a tree binds an inheritance class of its own:
  SSO's `OwnTenantInheritance`, bound by the application, is kept by the binding rule but reported by the check while
  SSO's enforcement is on (decision recorded here).
- Gaps in the members that installation and the checks work around:
  - Audit-log's `capture.laravel.except_guards` is a literal list with no environment variable, so `iam:install` can
    write it only into a `config/audit-log.php` it has just published, and an application that published its own
    edits it by hand; a comma-separated variable read into the list would let the value be set without the file.
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
  - `laravel-authentication`'s mapping of each code sign-in method to its identifier type is private
    (`SignInMethodManager`), so `SendersCheck` names `email_code` with `email` and `phone_code` with `phone` itself; a
    public constant would let it read them.
  - SSO's `ConfigurationChecker` keeps the checks it was built with to itself, so
    `SsoCheckRegistration::isInForce()` reads them from its mangled properties (`get_mangled_object_vars()`) to know
    whether `sso:check` runs the bridge, failing closed if they cannot be read; a public reader of the checker's
    subjects would let it ask.
  - Audit-log's judgement of whether its retention can delete anything is `IntegritySchedule::prunes()`, a public
    method of a class marked `@internal`, which `SchedulesCheck` resolves from the container to note a prune switched
    off; audit-log's own `audit-log:check` notes the sealing, sweep and verification switched off but not the prune.
    A note of audit-log's own, or a public contract for the judgement, would let this package stop reading it.
  - No member publishes its migrations through `publishesMigrations()`, and `vendor:publish` compares only a whole file
    name, so recognising a migration by its base name lives in `MigrationLedger`. That is no member's defect: a member
    that moves to `publishesMigrations()`, which renames each file with the time it is published, is still recognised.

## Implementation Anchors

- `src/Console/InstallCommand.php`: `handle()`, `tablePrefix()`, `askForTablePrefix()`, `report()`.
- `src/Install/Installer.php`: `install()`, `offersTablePrefix()`, `publishTag()`, `publishFile()`, `writeAuditLog()`,
  `writeTablePrefix()`, `judgeTablePrefix()`, `OWED`; `src/Install/InstallReport.php` (`$conflicts`, `$notes`).
- `src/Install/Publications.php`: `all()`; `src/Install/Publication.php`; `src/Install/Enums/PublicationKind.php`.
- `src/Install/MigrationLedger.php`: `baseName()`, `copyOf()`, `namesakesOf()`.
- `src/Install/AuditLogConfiguration.php`: `write()`; `src/Install/AuthorizationTablePrefix.php`: `assertValid()`,
  `apply()`, `carries()`, `MAX_LENGTH`; `src/Exceptions/PublicationFailedException.php`: `forFile()`.
- `src/Scheduling/IamSchedule.php`: `register()`; `src/IamManager.php`: `schedule()`.
- `src/Console/CheckCommand.php`: `handle()`; `src/Checks/Checker.php`: `run()`, `MEMBER_COMMANDS`, `CHECKS`;
  `src/Checks/Contracts/Check.php`.
- `src/Checks/StorageCheck.php`, `src/Checks/MandatorySeamsCheck.php` (`checksFor()`, `holderOf()`,
  `isMemberDefault()`), `src/Bindings/SeamBinding.php` (`$accepted`), `src/Checks/SeamHolders.php` (`of()`,
  `isMembersOwn()`),
  `src/Checks/SsoBridgeFallbackCheck.php`, `src/Checks/ContextNamespacesCheck.php`, `src/Checks/AuditCheck.php`,
  `src/Checks/SendersCheck.php`, `src/Checks/CrossMemberConfigurationCheck.php`, `src/Checks/PlatformCheck.php`,
  `src/Checks/SchedulesCheck.php`.
- `src/Checks/SsoCheckRegistration.php`: `register()`, `isInForce()`; `src/Checks/Sso/SsoBridgeCheck.php`:
  `CAPABILITIES`.
- `src/Checks/AuthenticationConfigurationCheck.php`: `findings()`, `CHECKS`;
  `src/Checks/Contracts/AuthenticationCheck.php`; `src/Checks/Checker.php`: `RUNNING`; `src/IamServiceProvider.php`:
  `boot()`.
- The mandates: `src/Sso/SsoSeams.php` (`isInUse()`), `src/Mfa/ContextSeams.php`, `src/Tenancy/TenancySeams.php`
  (`isEnforcedOrRequired()`); `src/IamServiceProvider.php`: `seamProviders()`, `UNCHECKED_COMMANDS`,
  `registerConsole()`.
- `composer.json`: `require`.

## Authoritative Tests

- `tests/Feature/Console/InstallCommandTest.php` `testEveryMembersFilesArePublishedInTheirWorkingOrder`,
  `testRunningTwiceChangesNothing`, `testAMigrationPublishedUnderAnotherTimestampIsRecognised`,
  `testAnApplicationsMigrationSharingABaseNameIsNotTakenForTheMembers`, `testAFileAtAMigrationsPathIsNeverOverwritten`,
  `testAnExistingConfigurationFileIsKept`, `testTheAuditLogValuesAreWrittenIntoItsConfigurationPublished`,
  `testTheAuditLogValuesAreOwedWhenItsConfigurationIsKept`, `testAReshapedAuditLogConfigurationIsOwedItsValues`,
  `testAMalformedExclusionListRefusesTheRunWithNothingPublished`, `testTheRunEndsWithWhatTheApplicationStillOwes`,
  `testTheMigrationItemNamesEachMembersConnection`,
  `testATagNoProviderRegisteredFailsTheRun`, `testThePrefixOptionPrefixesTheAuthorizationTables`,
  `testAnInvalidPrefixRefusesTheRunWithNothingPublished`,
  `testAPrefixIsNotWrittenOnceAnAuthorizationMigrationIsPublished`, `testRunningTwiceWithThePrefixOwesNothing`,
  `testANamesakeOfAnAuthorizationMigrationIsNoConflictOnceThePrefixIsWritten`,
  `testANamesakeOfAnotherMembersMigrationStaysAConflictUnderThePrefix`,
  `testANamesakeStaysAConflictWhenThePrefixIsNotWritten`,
  `testANamesakeStaysAConflictWhenTheConfigurationWasPublishedBefore`,
  `testAPrefixIsOwedWhileTheConfigurationTagIsUnregistered`,
  `testInteractiveTheRunAsksForThePrefix`, `testWithoutInteractionNothingIsPrefixed`,
  `testAFileThatCannotBeCopiedStopsTheRunAndARunOnceWritablePublishesTheRest`,
  `testARunStoppedAfterAuditLogsConfigurationLeavesItsValuesWritten`,
  `testARunStoppedAfterTheAuthorizationConfigurationLeavesThePrefixWritten`,
  `testAFileThatCannotBeCopiedIntoItsDirectoryStopsTheRunAndLeavesTheErrorHandler`
- `tests/Unit/Install/MigrationLedgerTest.php` `testTheBaseNameDropsTheTimestampAndTheExtension`,
  `testACopyUnderAnotherTimestampIsRecognised`, `testAnApplicationsMigrationOfTheSameBaseNameIsANamesake`,
  `testOnlyTheDirectorysOwnPhpFilesAreRead`
- `tests/Unit/Install/PublicationsTest.php` `testEveryTagIsPublishedInItsWorkingOrder`
- `tests/Unit/Install/AuditLogConfigurationTest.php` `testTheGuardsAndTheRefusalAreWritten`,
  `testAFileWithoutTheDefaultsIsLeftAsItIs`
- `tests/Unit/Install/AuthorizationTablePrefixTest.php` `testEveryTableNameIsPrefixed`, `testAnInvalidPrefixIsRefused`,
  `testWhetherAConfigurationCarriesThePrefix`
- `tests/Integration/Install/PrefixedAuthorizationTablesTest.php` `testTheLongestPrefixMigratesEveryTable` (MySQL and
  PostgreSQL)
- `tests/Feature/Scheduling/IamScheduleTest.php` `testOnlyThePrunesAreScheduledWhileSsoIsNotInUseAndDeliveryIsSync`,
  `testSsosOperationsAreScheduledOnceWhileSsoIsInUse`,
  `testTheDrainIsScheduledEveryMinuteWhileDeliveryIsThroughTheOutbox`,
  `testAnyOtherDeliveryModeSchedulesNoDrain`, `testAuditLogsOwnSchedulesAreNeverRegisteredAgain`
- `tests/Feature/Console/CheckCommandTest.php` `testAConfiguredApplicationPasses`,
  `testAProblemOfThePackagesOwnFailsTheRun`, `testAMembersFailureFailsTheRun`,
  `testAStorageMismatchIsReportedRatherThanRefusedAtBoot`,
  `testABrokenAuthorizationSettingIsReportedRatherThanRefusedAtBoot`,
  `testSsosSideIsCheckedWhenSsosCheckDoesNotRunIt`
- `tests/Unit/Checks/CheckerTest.php` `testEveryCheckRunsAndTheRunPasses`, `testAMemberCommandFailingFailsTheRun`,
  `testAMemberCommandThrowingStopsTheRun`, `testAMissingMemberCommandFailsTheRun`,
  `testEachCheckIsReported`, `testTheMembersCommandsRunMarked`
- `tests/Feature/Checks/AuthenticationConfigurationCheckTest.php` `testAnErrorFailsAuthenticationCheck`,
  `testTheGuardOptionLimitsIt`, `testEachClosureIsGradedAsIamCheckGradesIt`, `testAThrowingCheckIsContained`,
  `testNothingIsRegisteredTwice`, `testIamCheckReportsEachProblemOnce`
- `tests/Feature/Authorization/AuthorizationSeamsTest.php`
  `testAnAuthorizationRegisteredAgainLeavesEveryAdapterBound`
- `tests/Feature/Checks/MandatorySeamsCheckTest.php` `testASeamLeftOnItsMembersDefaultFails`,
  `testAMandatorySeamIsCheckedWithItsCapabilityOff`, `testAResolvedMemberDefaultFails`,
  `testAnyClassOfAMembersOwnFails`, `testAnApplicationsClosureFails`, `testAnUnboundMandatorySeamFails`,
  `testAnAnonymousImplementationOfTheApplicationsOwnPasses`, `testAnAnonymousSubclassOfAMembersDefaultFails`,
  `testTheSeamsSsosCheckHoldsAreLeftToIt`, `testSsosOwnLinkStoreIsAcceptedOnTheLinkStorage`,
  `testTheLinksAreMandatoryWhileSsoIsInUse`,
  `testASeamIsMandatoryWhileATenantsRuleIsOn`, `testTheInheritanceIsMandatoryWhileATreeAndEnforcementAreOn`,
  `testEachSeamTheRuleKeptIsNoted`
- `tests/Unit/Checks/SeamHoldersTest.php` `testAClassStringBindingNamesItsClass`, `testAnInstanceNamesItsClass`,
  `testAScopedAdapterNamesTheAdapter`, `testBindingsLeadingBackToEachOtherNameNothing`,
  `testAChainLongerThanTheLimitNamesNothing`, `testAMembersClosureNamesItsDeclarer`,
  `testAnApplicationsClosureNamesNothing`, `testAClosureUsingTheContainersNamesNamesItsDeclarer`,
  `testAnAnonymousImplementationIsTheApplicationsOwn`, `testAnAnonymousSubclassNamesTheClassItExtends`
- `tests/Feature/IamServiceProviderTest.php` `testTheCommandsAreRegisteredInTheConsole`,
  `testThePackagesChecksOfSsosSideAreRegisteredWithSsosOwn`, `testEveryCapabilitysSeamsAreProvided`
- `tests/Feature/Checks/StorageCheckTest.php` `testAMemberKeyOnAnotherConnectionFails`,
  `testAMemberThatNeverRegisteredIsReported`, `testEveryIdentityModelMustLiveOnTheSharedConnection`,
  `testAGuardNamingNoProviderReadsTheDefaultProvidersModel`, `testAuditLogOnAnotherConnectionIsNoted`
- `tests/Feature/Checks/ContextNamespacesCheckTest.php` `testItRequiresSsoOnlyWhileSsoIsInUse`,
  `testANamespaceNobodyRegisteredFails`, `testAnMfaNamespaceNobodyRegisteredFails`
- `tests/Feature/Checks/AuditCheckTest.php` `testAuditLogAsItShipsFails`, `testWhatTheInstallWritesPasses`,
  `testWithTheMappersOffAuditLogsValuesAreStillEnforced`, `testGateCaptureOnFails`,
  `testAnAuditLogThatNeverRegisteredIsReportedAsMissing`
- `tests/Feature/Checks/SsoBridgeFallbackCheckTest.php` `testTheWholeBridgeRunsHereWhenSsosCheckDoesNotRunIt`,
  `testItDoesNotApplyWhileSsosCheckRunsTheBridge`, `testItDoesNotApplyWhileSsoIsNotInUse`,
  `testItAppliesWhereSsosCheckCannotBeRead`, `testACheckerOfSsosClassHoldingTheBridgeRunsIt`
- `tests/Feature/Checks/SendersCheckTest.php` `testACodeMethodNeedsAGatewayOnItsChannel`,
  `testACodeMethodWhoseTypeIsUnroutedIsRefused`,
  `testACodeFactorNeedsAGatewayOnItsChannel`, `testANamedGatewayMustImplementTheContract`
- `tests/Feature/Checks/CrossMemberConfigurationCheckTest.php` `testMfasOperationsMustBeDeclared`,
  `testEveryMfaApplicationMustBeAGuard`, `testEveryMfaApplicationMustBeAJwtGuard`,
  `testSsosOperationsMustBeDeclaredWhileSsoIsInUse`,
  `testSsosBulletsAreHeldBySsosCheck`, `testAuditLogsBulletsAreHeldByTheAuditCheck`,
  `testTheTenantResolverMustResolveWhileATenantsRuleReachesASession`, `testGrantsNeedNoResolverWhileSsoIsOff`,
  `testNoTenantsRuleRequiresNoResolver`,
  `testTheResourceTenantResolverIsNotedWhilePeopleActInTenants`,
  `testAResourceTenantResolverTheApplicationNamesIsNotNoted`
- `tests/Unit/Checks/PlatformCheckTest.php` `testAMissingExtensionIsReported`,
  `testAProviderWhoseRegistryIsNotLinkedIsReported`, `testAProviderWhoseRegistryCannotBeReadIsReported`
- `tests/Feature/Checks/SchedulesCheckTest.php` `testAuditLogsRunsSwitchedOffAreNotedUntilSomethingRunsThem`,
  `testThePrunesAreNotedUntilThePackageSchedulesThem`, `testSsosPruneSwitchedOffIsNotedWithItsCause`,
  `testAuditLogsPruneSwitchedOffIsNotedWhileItsRetentionCanDelete`,
  `testAuditLogsPruneIsNotedWithItsCauseWhenRetentionCannotBeJudged`,
  `testAScheduleThatCannotBeBuiltIsOneProblemNamingItsCause`
- `tests/Feature/Checks/SsoCheckRegistrationTest.php` `testTheCheckIsRegisteredAfterSsosOwnInEveryProviderOrder`,
  `testARegistrationOnceResolvedAddsAtOnceAndKeepsTheApplicationsCheck`,
  `testACheckTheApplicationRegistersAfterThePackagesIsKept`, `testNothingIsAddedWhileSsosProviderHasNotRegistered`,
  `testSsosBootCheckRunsTheBridgeOutsideTheConsoleInEveryOrder`, `testSsoRegisteredOnceBootedStillRunsTheBridge`,
  `testResolvingSsosCheckerAddsTheCheckOnlyOnceBooted`, `testSsosCheckReportsIt`
- `tests/Unit/Checks/Sso/SsoBridgeCheckTest.php` `testItAppliesOnlyWhileSsoIsInUse`, `testEachApplicationIsChecked`,
  `testTheBaseUrlAndTheStorageConnectionAreLeftToTheirOwners`, `testTheMandatorySeamsAreChecked`

## Change Triggers

- A member adding, renaming or removing a publishing tag, a migration, or its namespace: `Publications` follows, and
  `MigrationLedger`'s recognition of a copy by the namespace it names.
- A member reshaping the defaults `AuditLogConfiguration` and `AuthorizationTablePrefix` write over, or
  `laravel-authorization` adding a table or a longer derived name: `MAX_LENGTH` follows.
- A member scheduling work of its own, or leaving more to the application: `IamSchedule` follows, and so does
  `iam:check`'s report of schedules switched off.
- A member adding a PHP extension or a Composer plugin: `composer.json` follows.
- A member adding a check command, a check of its own that covers one of this package's (glue, not policy), or a
  public way to add a check: `Checker` and the checks follow.
- `laravel-authentication` changing `ConfigurationChecks`, `ConfigurationCheck` or `ConfigurationFinding`, or a check
  gaining or losing a part of `laravel-authentication`'s side: `AuthenticationConfigurationCheck` and the
  `AuthenticationCheck` methods follow.
- A member renaming a mandatory seam's default, a mandate changing (`AccessMandates`' application access and scope
  registry among them), or
  MFA or `laravel-authorization` standing their boot validation aside for `iam:check`: `MandatorySeamsCheck`,
  `ContextNamespacesCheck` and `CheckCommand` follow.
- SSO changing `ConfigurationChecks::add()`, `Features::isInUse()` or the meaning of `FreshnessOperation`:
  `SsoCheckRegistration`, `SsoBridgeFallbackCheck`, `SsoSeams::isInUse()` and `CrossMemberConfigurationCheck` follow.
- SSO binding a link storage default of its own, or its guide binding the link storage to another class: the link
  storage row's `accepted` list follows.
- `laravel-authorization` binding its resource tenant resolver so the configured class can be read from its binding:
  `CrossMemberConfigurationCheck` follows. `authorization:check` exiting `0` on a refusal or an incomplete report, or
  throwing out of the console kernel's `call()` rather than ending with its exit code: `Checker` follows.
- A member closes one of the gaps listed above: the workaround it names goes.
