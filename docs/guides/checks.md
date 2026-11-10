# Checks

`php artisan iam:check` checks the whole suite's configuration: every member's own check, then this package's. Run it
on every deploy, after `migrate` and before traffic reaches the new release. It exits `0` only when every check passes;
a note tells you something worth knowing and never fails the run.

Each of this package's checks reads configuration and the container only: never a request, a guard's caller or the
database. The members' checks, which `iam:check` runs first, read what their own guides say: audit-log's reads the
schema of its tables, so `iam:check` needs the database, after `migrate`. This package's messages name keys, seams,
guards, connections and classes, never a secret or credential, so the output is safe to keep in a deploy log; a
connection's or a model's name may appear in it.

- [Reading the output](#reading-the-output)
- [The members' checks](#the-members-checks)
- [In laravel-authentication's check](#in-laravel-authentications-check)
- [storage](#storage)
- [seams](#seams)
- [sso](#sso)
- [context](#context)
- [audit](#audit)
- [senders](#senders)
- [configuration](#configuration)
- [platform](#platform)
- [schedule](#schedule)
- [What later releases add](#what-later-releases-add)

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
you run it yourself, and one that exits non-zero fails the run. One that is not registered is reported as
`<command> is not registered.` and fails the run too: every member is required. What each member checks, and how to fix
it, is in that member's guides.

## In laravel-authentication's check

This package adds its checks of `laravel-authentication`'s side to `authentication:check`, so running that command on
its own reports them too, after `laravel-authentication`'s own:

- from [storage](#storage), the identity model of each guard;
- from [seams](#seams), the mandatory seams that are `laravel-authentication`'s contracts (its scope registry,
  application access, passkey factor gate and the like), and the note of each one the rule kept with your binding;
- from [context](#context), every namespace;
- from [configuration](#configuration), the tenant resolver, and the MFA and SSO applications named after each guard.

Each is reported with its subject, as `[iam:<subject>]`, and, when it is about one guard, after that guard's name:

```text
[api] [iam:configuration] MFA's freshness operations [mfa.add_factor] are not declared for guard [api] under ...
```

A problem fails `authentication:check`, as it fails `iam:check`, and a note is shown as a warning. `--guard` limits
what is about a guard to the guards it names; the rest is reported whatever `--guard` says. Fix each as its section
below says. A check of this package's that cannot run is reported as *The check [...] failed: ...*, naming the check
and the class of what went wrong; `iam:check` reports the cause.

`iam:check` runs `authentication:check` too, but reports these under `iam` alone, so each problem appears once. The
members' storage keys, the shared connection, and an MFA or SSO application that names no guard
`authentication:check` checks are left to `iam:check`.

## storage

The storage connection is one connection (see [Configuration](configuration.md#storage)). Boot refuses a mismatch,
but stands aside while `iam:check` runs, so this check can report it. Each message is shown in italics, with what it
names elided.

- `laravel-authentication`, `laravel-mfa` or `laravel-sso` has not registered (`MemberNotRegisteredException`):
  register every member's service provider before the application finishes booting, or let package discovery register
  them.
- *... names [...], but iam.storage.connection names [...]* (`StorageConnectionMismatchException`): a member's own
  storage key names another connection. Unset the member's key, or set it to the same connection.
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

This package adds a check of SSO's side to SSO's own checks, under `iam`, so SSO runs it at boot, as each worker command
starts and in `sso:check`, which reports it as `[iam]`. It applies only while SSO is in use (`sso.features.saml2` or
`sso.features.oidc` on), so it can fail SSO's boot only then. Where your application keeps a check of its own under
`iam`, or SSO's checks do not run the bridge for another reason, `iam:check` runs the same tests itself, under `[sso]`.

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

- *laravel-audit-log's provider (...) is not registered, so no member event is recorded: ...*: register audit-log's
  service provider, or stop package discovery leaving it out.
- *The audit mappers are not registered with laravel-audit-log; ...*: register this package's provider before the
  application boots, or turn `iam.audit.mappers` off to map the members' events yourself. Only this one follows the
  switch.
- *Guards [...] are missing from `audit-log.capture.laravel.except_guards`, ...*: add every `jwt` and `api_key` guard
  to audit-log's exclusions, or each of their sign-ins is recorded twice. `iam:install` writes the guards it finds.
- *`audit-log.capture.gate.enabled` must be false, so each authorization decision is recorded once, ...*: turn
  audit-log's Gate capture off, so each decision is recorded once, after a later release maps `laravel-authorization`'s
  events. Until then **no authorization decision is recorded**, your own `Gate` checks included (see
  [Authorization](authorization.md#what-waits)). If you need the records now, listen to `laravel-authorization`'s
  `SineMacula\Laravel\Authorization\Events\AuthorizationFailed` yourself and record each denial with
  `AuditLog::record()` under a code you define ([The audit trail](audit-trail.md#no-double-records)).
- *`audit-log.definitions.require_registered` must be true, ...*: turn it on, so a code without a definition is refused
  rather than recorded unchecked. `iam:install` writes it.
- Any value of `iam.audit.alerts` that names no alert, or no listener class, or a listener class with neither `handle()`
  nor `__invoke()`: name a listener class, or a list of them, for each alert ([Configuration](configuration.md#audit)).
  The check builds nothing, so a name you bound in the container yourself passes it, and its shape is checked only when
  its event is dispatched; name the class rather than a binding to have it checked here.

## senders

Every code the suite sends has a gateway to go through.

- *`iam.delivery.types` must map identifier types to channels.* or *`iam.delivery.types.<type>` must name a channel:
  ...*: map each identifier type to `email` or `sms`.
- *`iam.delivery.email` must name a class implementing ...* (or `sms`): name your gateway's class, which must implement
  `SineMacula\Laravel\Iam\Contracts\EmailGateway` (or `SmsGateway`).
- *Guards [...] allow `email_code`, but `iam.delivery.types` routes no `email` type to a channel.* (or `phone_code` and
  `phone`): route the identifier type to a channel in `iam.delivery.types`.
- *... send on sms with no gateway: name one in `iam.delivery.sms`, or bind ...* (or email): a guard allowing a code
  sign-in method, or an MFA application enabling the factor type, sends on the channel, and no gateway takes it. Name
  your gateway in `iam.delivery.sms` or `iam.delivery.email`, or bind it.

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
  SineMacula\Laravel\Authentication\Tenancy\ResolveNoTenant while SSO's enforcement is on or a tenant MFA requirement
  is named: ...*: MFA's tenant requirement, a tree's changes and SSO's revocation resolve a session's tenant through
  `laravel-authentication`'s tenant resolver, whose default resolves none, so every MFA-gated request from a session
  in a tenant would answer a server error. Bind a resolver that resolves every tenant id to the tenant whose
  `getTenantIdentifier()` is that id, even if your principals act only in their own tenant (see
  [Provisioning and tenancy](provisioning-and-tenancy.md#the-tenant-resolver)). A resolver bound through a closure is
  not built, so the check passes it.

A provider attribute beyond SSO's standard mapping (`sso.mapping.custom_attributes`) depends on each connection's
mapping, which lives in the database, so no check can see it; nor can one see your routes. See
[An example application](example-application.md).

## platform

The PHP extensions and the Composer plugin SSO needs are in place.

- *The PHP extension ext-... is not loaded.*: install or enable the extension in the PHP that runs the application.
  The suite needs `bcmath`, `curl`, `dom`, `hash`, `libxml`, `mbstring`, `openssl` and `zlib`.
- *The Composer plugin simplesamlphp/composer-xmlprovider-installer is not installed.*: require it, as SSO does.
- *The Composer plugin ... has not registered the XML elements of ...; allow it under `config.allow-plugins` ...*:
  allow the plugin in your application's `composer.json` and run `composer install` again
  ([Installation](installation.md)).
- *The XML element registry of ... cannot be read, ...; install it again.*: reinstall the package named.

## schedule

Reports notes only, since something no check can see may start a run; the one failure is a schedule that cannot be
built.

- *The application's schedule cannot be built, so no run on it is checked: ...*: fix the cause named, usually a
  malformed `sso.operations.cadence.*` value, which stops the scheduler too.
- Note: *`mfa:prune` is not on the schedule; call `Iam::schedule($schedule)` from the application's `withSchedule()`.*
  (and the same for `sso:prune` while SSO is in use, and for `audit-log:drain --until-empty` while
  `audit-log.delivery.mode` is `outbox`): register the scheduled work ([Operations](operations.md)).
- Note: *SSO's operations schedule runs `sso:prune` only while `sso.operations.cadence.prune` gives a cron expression,
  ...*: set the cadence, or schedule `sso:prune` yourself.
- Note: *audit-log schedules its own `audit-log:seal` only while its setting gives a cron expression, ...* (and the
  same for `audit-log:seal --sweep` and `audit-log:verify`): turn audit-log's own schedule for it on, or schedule the
  command yourself. See [laravel-audit-log: operations][audit-log-operations].
- Note: *audit-log schedules its own `audit-log:prune` only while `audit-log.retention.schedule` gives a cron
  expression, and no event on the schedule runs it, though its retention can delete entries.*: shown only while
  audit-log's retention can delete entries, so a retention that keeps everything is never noted. Turn
  `audit-log.retention.schedule` on, or schedule `audit-log:prune` yourself.
- Note: *audit-log cannot judge whether its retention can delete entries (...), and no event on the schedule runs
  `audit-log:prune`; ...*: audit-log refused to answer, and the brackets name the class of its cause. Settle
  `audit-log.retention.*` as audit-log's guide says, or schedule `audit-log:prune` yourself.

## What later releases add

- The configuration check requires `laravel-authorization`'s resource tenant resolver to name this package's adapter,
  `authorization.connection` joins the storage check, `authorization:prune` joins the schedule, and audit-log's access
  policy is answered from `laravel-authorization`. See [Authorization](authorization.md#what-waits).

[audit-log-operations]: https://github.com/sinemacula/laravel-audit-log/blob/master/docs/guides/operations.md
[authentication-configuration]: https://github.com/sinemacula/laravel-authentication/blob/master/docs/guides/configuration.md
