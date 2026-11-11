# Checks

`php artisan iam:check` checks the whole suite's configuration: every member's own check, then this package's. Run it
on every deploy, after `migrate` and before traffic reaches the new release. It exits `0` only when every check passes;
a note tells you something worth knowing and never fails the run. This package's checks appear only under `iam:check`:
no member's own command reports them.

Each of this package's checks reads configuration and the container only: never a request, a guard's caller or the
database. The members' checks, which `iam:check` runs first, read what their own guides say: audit-log's reads the
schema of its tables, so `iam:check` needs the database, after `migrate`. This package's messages name keys, seams,
guards, connections and classes, never a secret or credential, so the output is safe to keep in a deploy log; a
connection's or a model's name may appear in it.

- [Reading the output](#reading-the-output)
- [The members' checks](#the-members-checks)
- [storage](#storage)
- [seams](#seams)
- [sso](#sso)
- [context](#context)
- [audit](#audit)
- [configuration](#configuration)
- [schedule](#schedule)

## Reading the output

```text
authentication:check
...
iam
[storage] OK
[seams] note: SineMacula\Laravel\Mfa\Contracts\StepUp keeps the application's binding, not this package's adapter.
[sso] not applied
[audit] Guards [admin] are missing from `audit-log.capture.laravel.except_guards`, ...
A check failed.
```

Each of this package's checks reports under its subject, in brackets:

- `OK`: it found nothing.
- `not applied`: it does not apply to this configuration (SSO's checks while SSO is not in use, say).
- A message, in red: a problem, which fails the run. Every check runs every one of its tests, so one run reports every
  problem.
- `note:` and a message: something worth knowing, which does not fail the run.

Fix what each section below says, then run `iam:check` again.

## The members' checks

`iam:check` first runs each member's own check command through the console, in this order: `authentication:check`,
`authorization:check`, `mfa:check`, `sso:check` and `audit-log:check`. Each reports in its own words, as it does when
you run it yourself, and one that exits non-zero fails the run. `authorization:check` reports `laravel-authorization`'s
settings, seams, grant hooks and connection, and exits `1` when it refuses a setting and `3` when it could not complete
its report: either fails the run. Each adapter this package binds over one of `laravel-authorization`'s contracts is
declared to that report, so its seam reads `declared by laravel-iam` while the adapter is still what the contract
resolves to (see [Authorization](authorization.md#pruning-and-checks)). Run as the command itself (`php artisan
iam:check`), `iam:check` also makes `laravel-authorization` boot for diagnosis, so a broken authorization setting is
reported by `authorization:check` and fails the run rather than stopping the application before the check starts. One
that is not registered is reported as
`<command> is not registered.` and fails the run too: every member is required. What each member checks, and how to fix
it, is in that member's guides.

## storage

The storage connection is one connection (see [Configuration](configuration.md#storage)). Boot refuses a mismatch,
but stands aside while `iam:check` runs, so this check can report it. Each message is shown in italics, with what it
names elided.

- *... names [...], but iam.storage.connection names [...]* (`StorageConnectionMismatchException`): a member's own
  storage key names another connection, `laravel-authorization`'s `authorization.connection`
  (`AUTHORIZATION_DB_CONNECTION`) included. Unset the member's key, or set it to the same connection.
- *`iam.storage.connection` names a connection `database.connections` does not configure.*: configure the connection,
  or name one that exists.
- *The identity model ... is no Eloquent model.*: the user provider of a `jwt` or `api_key` guard names a model that is
  not an Eloquent model. Name an Eloquent identity model.
- *The identity model ... lives on another connection than `iam.storage.connection` names.*: set the model's
  `$connection` to the storage connection, or leave it unset when that is the default connection. A guard that names no
  provider is checked through `auth.defaults.provider`.
- Note: *`audit-log.storage.connection` names another connection than `iam.storage.connection`: ...*: the trail may
  live on its own connection, but audit-log's refusal of a read of the trail inside a change then does not cover it.

The check cannot see your principal models, which no setting names: keep them on the storage connection yourself.

## seams

Every mandatory seam is bound to something that does its duty ([Bindings](bindings.md) lists which seams are
mandatory, and when). The check reads the live binding without building anything.

- *... is unbound; bind ..., or an implementation of your own, to it.*: bind the adapter it names, usually by turning
  the capability's switch back on (`iam.adapters.mfa`, `iam.adapters.sso` or `iam.adapters.authorization`), or bind
  your own implementation.
- *... is still bound to ..., its member's permissive or inert default; ...*: the member's default would leave the duty
  undone. Turn the switch on, or bind your own implementation.
- *... is bound through a closure, whose implementation cannot be read without building it; ...*: bind the seam by
  class name or as an instance, so the check can tell what it is.
- Note: *... keeps the application's binding, not this package's adapter.*: a binding of yours was in place before
  this package registered, so the adapter was never bound. Make sure your implementation keeps the adapter's duties
  ([Bindings](bindings.md#replacing-a-binding)).

`laravel-authentication`'s scope registry and `laravel-authorization`'s session policy source are mandatory while a
guard accepts `api_key` or `client_credentials`, as the bound `ApplicationPolicy` says (yours, if you replace it to read
a guard's methods from somewhere else), and `laravel-authentication`'s application access while
`authorization.application_access` maps an application to a permission: left on the members' defaults, a credential
could carry scopes that name no permission, a machine's checks would be capped by nothing, whatever scopes its
credential was issued, and every principal could use an application its grants keep it from. The session policy
source's default, `NoSessionPolicy`, is refused whether `iam.adapters.authorization` is on or off, and whether you bind
it by name; a source you name in `authorization.session.source` is read through `laravel-authorization`'s own binding,
so it passes. An application the map leaves out is open to every principal whatever the mandate says (see
[Authorization](authorization.md#access-contracts)).

While SSO is in use, the mandatory seams of SSO and tenancy are checked by the SSO bridge (below) instead, so each seam
is reported once.

## sso

Applies only while SSO is in use (`sso.features.saml2` or `sso.features.oidc` on).

- *`sso.applications.<name>` is served by SSO, but its guard does not list `external_provider` among
  laravel-authentication's sign-in methods.*: add `external_provider` to the methods of the guard of the same name
  (`auth.guards.<name>.application.methods`), or stop serving the application through SSO.
- *`sso.applications.<name>.unlinked_handoffs` must stay off under laravel-iam: an unlinked result is provisioned or
  refused, never handed off.*: set it to `false`, and name a provisioner instead
  ([Provisioning and tenancy](provisioning-and-tenancy.md)).
- Every mandatory seam of SSO and tenancy, with the messages under [seams](#seams).

## context

Always applies: the `mfa` namespace is required in every application, the `sso` namespace while SSO is in use.

- *No contributor is registered under the `mfa` namespace of the authentication context; turn `iam.adapters.mfa` on,
  or register your own.*: the `mfa.*` keys of a session's authentication context have no contributor, so a policy
  reading them reads nothing. Turn the switch on, or register a contributor of your own under `mfa`.
- *No contributor is registered under the `sso` namespace of the authentication context; turn `iam.adapters.sso` on,
  or register your own.*: the `sso.*` keys of a session's authentication context have no contributor. Turn the switch
  on, or register a contributor of your own under `sso`.

## audit

Always applies, whatever `iam.audit.mappers` says, except where noted.

- *The audit mappers are not registered with laravel-audit-log; ...*: register this package's provider before the
  application boots, or turn `iam.audit.mappers` off to map the members' events yourself. Only this one follows the
  switch.
- *Guards [...] are missing from `audit-log.capture.laravel.except_guards`, ...*: add every `jwt` and `api_key` guard
  to audit-log's exclusions, or each of their sign-ins is recorded twice. `iam:install` writes the guards it finds.
- *`audit-log.capture.gate.enabled` must be false, so no authorization decision is recorded twice: ...*: turn
  audit-log's Gate capture off. This package maps `laravel-authorization`'s decision events, the `Gate` checks it
  answers among them, so audit-log's own capture would record each of them again
  ([The audit trail](audit-trail.md#no-double-records)).
- *`audit-log.definitions.require_registered` must be true, ...*: turn it on, so a code without a definition is refused
  rather than recorded unchecked. `iam:install` writes it.

## configuration

The members' settings agree with each other.

- *`mfa.applications.<name>` names no guard in `auth.guards`: MFA's application is the guard of the same name.*: name
  each MFA application after the guard it serves, or add that guard.
- *`mfa.applications.<name>` names a guard in `auth.guards` whose driver is not `jwt`: MFA's application is a guard
  that holds sessions.*: an MFA application is a `jwt` guard of `laravel-authentication`'s, the one driver that holds
  sessions, and every MFA call for one on another driver (`api_key` or `session`, say) is refused at runtime. Name the
  MFA application after a `jwt` guard, or remove it.
- *...'s freshness operations [...] are not declared for guard [...] under `authentication.freshness` or the guard's
  `freshness`.*: declare MFA's `mfa.*` operations for every MFA application's guard, and, while SSO is in use, SSO's
  `sso.*` operations for every SSO application's guard, under `authentication.freshness` or the guard's own `freshness`
  block. See [laravel-authentication: configuration][authentication-configuration].
- *SineMacula\Laravel\Authentication\Contracts\TenantResolver is still bound to
  SineMacula\Laravel\Authentication\Tenancy\ResolveNoTenant while SSO's enforcement is on, a tenant MFA requirement is
  named, laravel-authorization's grants are reported to SSO's scope widening, or laravel-authorization reads the tenant
  tree: ...*: MFA's tenant requirement, a tree's changes and SSO's revocation resolve a session's tenant through
  `laravel-authentication`'s tenant resolver; while the authorization and SSO adapters are both on (the default), the
  grant hook resolves the tenant of every grant that widens an identity's scope through it; and while the authorization
  adapters are on and you name or bind a tenant tree, `laravel-authorization`'s tree resolves every tenant it asks about
  through it. Its default resolves none, so every MFA-gated request from a session in a tenant, every grant to an
  identity or a principal's first grant in a tenant, every tenant-scoped check and every move of a tenant would answer
  a server error. Bind a resolver that resolves every tenant id to the tenant whose
  `getTenantIdentifier()` is that id, even if your principals act only in their own tenant (see
  [Provisioning and tenancy](provisioning-and-tenancy.md#the-tenant-resolver)). A resolver bound through a closure is
  not built, so the check passes it.
- Note: *SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver is still
  SineMacula\Laravel\Authorization\Resolvers\NoResourceTenant while people act in tenants: ...*: shown while your
  memberships are bound or named. `laravel-authorization`'s default resolver knows no record's tenant, so a grant in
  one tenant reaches another tenant's records unless each model declares its tenancy or names its tenant. Name your
  resolver in `authorization.resource_tenant_resolver`, bind the contract yourself, or leave it where every model the
  checks name declares its tenant (see [Authorization](authorization.md#tenants)).

A provider attribute beyond SSO's standard mapping (`sso.mapping.custom_attributes`) depends on each connection's
mapping, which lives in the database, so no check can see it; nor can one see your routes. See
[An example application](example-application.md).

## schedule

Reports a note only, since something no check can see may start a run.

- Note: *Runs [...] are not on the schedule; call `Iam::schedule($schedule)` from the application's `withSchedule()`.*:
  `mfa:prune` and `authorization:prune`, and `audit-log:drain --until-empty` while `audit-log.delivery.mode` is
  `outbox`, are not on the schedule. Register the scheduled work ([Operations](operations.md)).

A schedule that cannot be built, usually through a malformed `sso.operations.cadence.*` value, fails the run with its
cause.

[authentication-configuration]: https://github.com/sinemacula/laravel-authentication/blob/master/docs/guides/configuration.md
