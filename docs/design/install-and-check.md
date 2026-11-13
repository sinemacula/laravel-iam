# Install and Check

How `iam:install` publishes the suite into an application, how `Iam::schedule()` registers the members' scheduled work,
and how `iam:check` runs every member's check and this package's own.

## Installation

- `iam:install` publishes every member's `-config` and `-lang` tags, and `iam-config`, through `vendor:publish`, which
  keeps a file already there.
- Each member's `-migrations` tag is expanded to its files and filtered through `MigrationLedger`: a migration counts as
  published when a file beside its destination shares its base name (the name without the timestamp) and the member's
  namespace, since `vendor:publish` compares whole file names. So running it twice, or after installing the members
  directly, publishes nothing new. An application's own migration of the same base name is not a copy.
- A tag no provider registered is reported and the run exits 1; the rest is still published.
- The `laravel-authorization` table prefix comes from `--prefix` or a prompt. It is checked with
  `TableNames::isValidPrefix()` before anything is published, and written only into an authorization configuration
  published in the same run while none of its migrations is published, since migrated tables would lose their names.
- The run ends with what the application still owes, each item linking to the installation guide.

## Scheduling

- `Iam::schedule()` registers `mfa:prune` and `authorization:prune` daily, SSO's `OperationsSchedule::register()`, and
  `audit-log:drain --until-empty` every minute while audit-log delivers through its outbox.
- Audit-log's own seal, sweep, verify and prune are never registered again; it schedules them itself.
- No task has a cache mutex: every command is safe on several servers, and a stale mutex would suppress maintenance.

## Platform

`composer.json` requires the union of the members' `ext-*` requirements. Allowing SSO's Composer plugin is owed by the
application, since only the root `allow-plugins` counts.

## Checks

- `iam:check` hands its output to `Checker::run()` and exits 0 only when everything passed.
- It first runs the members' commands: `authentication:check`, `authorization:check`, `mfa:check`, `sso:check` and
  `audit-log:check`. Their checks stay theirs. Any non-zero exit, or a command not registered, fails the run.
- `iam:check` is declared to laravel-authorization as a composing command, so a broken authorization setting is
  reported by `authorization:check` instead of throwing at boot.
- This package's checks run only under `iam:check`. Each implements `Checks\Contracts\Check`; every closure runs, so one
  run reports every problem. A closure throws for a problem or returns a note that does not fail the run. Checks read
  configuration and the container only, and never print a secret.
  - `StorageCheck`: every member key, `authorization.connection` included, on the shared connection, and each `jwt`
    or `api_key` guard's user model on it. Audit-log on another connection is a note.
  - `MandatorySeamsCheck`: every seam a capability declares mandatory is bound and not its member's default, whatever
    the capability's switch says. While SSO is in use the SSO and tenancy rows are left to `SsoBridgeCheck`.
  - `SsoBridgeCheck`: while SSO is in use, each SSO application's guard allows `external_provider`, no application has
    `unlinked_handoffs` on, and the SSO and tenancy mandatory seams hold.
  - `ContextNamespacesCheck`: the `mfa` namespace has a contributor, and `sso` too while SSO is in use.
  - `AuditCheck`: every `jwt` and `api_key` guard excluded from audit-log's capture, Gate capture off and
    `require_registered` on, whatever the mappers switch says.
  - `CrossMemberConfigurationCheck`: every MFA application is a `jwt` guard; MFA's and, while SSO is in use, SSO's
    freshness operations are declared; the tenant resolver is bound while a tenant rule, a widening grant or a tenant
    tree needs it. A resource tenant resolver left on its default is a note while the application has memberships.
  - `SchedulesCheck`: a note for each run `IamSchedule` registers that nothing on the schedule runs. A schedule that
    cannot be built fails.
- Boot's storage refusal stands aside under `iam:check`, so `StorageCheck` reports it instead.

## Edge cases

- `authorization:prune` is registered whatever `iam.adapters.authorization` says: grants expire either way.
- A seam is a member's default only when the member's `isPackageDefault()` says so.
- A configuration MFA's boot check refuses stops `iam:check` with MFA's message and a non-zero exit, without this
  package's report.

## Member gaps

- `laravel-mfa`: its boot check stands aside only for `mfa:check` and the configuration commands, not for a composing
  package's check command.
