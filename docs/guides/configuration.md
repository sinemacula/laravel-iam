# Configuration

Every key of `config/iam.php`, what it does and what it defaults to. `iam:install` publishes the file
(`php artisan vendor:publish --tag=iam-config` publishes it alone). The members' own keys are in their own guides; this
guide names a member key only where this package reads or writes it.

The file is read as the package registers, before most of the members have merged their own configuration, so set
every key in the configuration file or the environment, never from a service provider. A change takes effect on the
next boot: a deploy, or a restart of every worker (see [Operations](operations.md)).

- [Storage](#storage)
- [Adapters](#adapters)
- [Tenancy](#tenancy)
- [Provisioning](#provisioning)
- [Delivery](#delivery)
- [SSO](#sso)
- [Audit](#audit)
- [Transactions](#transactions)
- [Workers](#workers)

## Storage

| Key                      | Default | Environment              | What it does                                                                        |
|--------------------------|---------|--------------------------|-------------------------------------------------------------------------------------|
| `iam.storage.connection` | `null`  | `IAM_STORAGE_CONNECTION` | The one connection every member's tables live on; `null` is the default connection. |

The connection is written into `authentication.storage.connection`, `mfa.storage.connection`,
`sso.storage.connection` and `laravel-authorization`'s `authorization.connection` (`AUTHORIZATION_DB_CONNECTION`)
wherever a member leaves its own key unset, so a change that spans members, a grant made with a provisioned membership
among them, runs in one transaction. A member key that names another connection refuses boot with
`StorageConnectionMismatchException`: unset the member's key, or set it to the same connection. `laravel-audit-log` may
keep its own connection; `iam:check` notes it.

Your identity models, and every principal model your guards resolve, must live on this connection too, or a sign-in
and the session it writes cannot commit together. `iam:check` checks the identity models of every guard; it cannot
see your principal models, so set their `$connection` (or leave it unset, on the default connection) yourself.

Keep it fixed while the application runs: moving the tables is a deploy, with a migration and a restart of every
worker.

## Adapters

| Key                          | Default | Environment                  | What it does                                                                                                                                                                                                                 |
|------------------------------|---------|------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `iam.adapters.mfa`           | `true`  | `IAM_ADAPTERS_MFA`           | Binds `laravel-authentication` and MFA through each other's seams, passkeys and MFA's context.                                                                                                                               |
| `iam.adapters.sso`           | `true`  | `IAM_ADAPTERS_SSO`           | Binds `laravel-authentication` and SSO, the tenant authentication policy, and the membership and tree seams.                                                                                                                 |
| `iam.adapters.authorization` | `true`  | `IAM_ADAPTERS_AUTHORIZATION` | Binds `laravel-authorization` to the other members: its subject, context, requirement checker and session policy, its step-up, the access seams, its identity directory, tree and grant hook, and audit-log's access policy. |

Each is read leniently, as the members read a switch an environment variable fills: `false`, `0`, `off` and `no`
turn one off, and anything else, an empty value included, leaves it on. Every seam each one binds, and what turning it
off leaves undone, is in [Bindings](bindings.md). Turn one off only to bind every one of its seams yourself:
`iam:check` still holds you to the mandatory ones.

SSO's freshness judges only the caller SSO is handed. Hand a call into SSO that asks for freshness (a management
helper, the start of a link flow) the caller it runs for, as SSO names it:

```php
use Illuminate\Auth\AuthenticationException;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Sso\Domains\DomainService;

$caller = Auth::caller() ?? throw new AuthenticationException;

$result = app(DomainService::class)
    ->remove($tenantId, $connectionId, $domain, $client, Iam::callers()->of($caller));
```

Without it, SSO judges no session fresh and refuses with `freshness_required`. Only the session the caller's access
credential holds, of the caller's own guard and identity, is judged: a refresh or pending credential is `stale`. Call
`Iam::callers()->of()` with no transaction open on the storage connection: a caller named inside one carries no
session, so it is `stale`. See [Authentication and SSO](authentication-and-sso.md#ssos-own-calls-that-ask-for-freshness).

## Tenancy

| Key                           | Default | Environment | What it does                                                                            |
|-------------------------------|---------|-------------|-----------------------------------------------------------------------------------------|
| `iam.tenancy.mfa_requirement` | `null`  | None        | Your tenant MFA requirement, a class implementing `Iam\Contracts\TenantMfaRequirement`. |
| `iam.tenancy.memberships`     | `null`  | None        | Your memberships, a class implementing `Iam\Contracts\Memberships`.                     |
| `iam.tenancy.tree`            | `null`  | None        | Your tenant tree, a class implementing `Iam\Contracts\TenantTree`.                      |

Classes are named relative to `SineMacula\Laravel\`. Each is optional, and a class bound in the container by the time
every service provider has registered counts as named. Any value that is no class name fails closed.

- The tenant MFA requirement is the one answer MFA's tenant requirement and `laravel-authentication`'s tenant
  authentication policy are both given. It answers for exactly the tenant asked: this package applies no inheritance
  down a tree. Name none and no tenant requires a further factor; SSO's enforcement still applies.
- The memberships answer SSO's tenant membership, link eligibility and the membership half of its principal scope.
  Name none and SSO's defaults stay: no membership, no `link`, no linking by a verified domain.
- The tree lets a tenant inherit SSO's enforcement from the nearest tenant above it that has a rule, and is
  `laravel-authorization`'s tree, so a grant with its subtree reaches the tenants below. Name none and every tenant
  stands alone, `laravel-authorization` keeping its own flat tree. With the authorization adapters on, a tree needs a
  tenant resolver, which `iam:check` requires.

Report every change to a tenant's answer ([Provisioning and
tenancy](provisioning-and-tenancy.md#the-tenant-mfa-requirement)), every move in the tree ([Provisioning and
tenancy](provisioning-and-tenancy.md#the-tenant-tree)) and every exemption your `EnforcementExemption` grants or
withdraws ([Authentication and SSO](authentication-and-sso.md#the-tenant-policy)), or sessions that no longer meet the
answer keep acting in the tenant.

## Provisioning

| Key                               | Default | Environment | What it does                                                                                                                                                          |
|-----------------------------------|---------|-------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `iam.provisioning.provisioner`    | `null`  | None        | Your provisioner, a class implementing `Iam\Contracts\Provisioner`.                                                                                                   |
| `iam.provisioning.groups.mapping` | `null`  | None        | Your group mapping, a class implementing `Iam\Contracts\GroupMapping`: the roles a provider's groups give a person in the connection's tenant.                        |
| `iam.provisioning.groups.map`     | `[]`    | None        | While no mapping is named or bound, each group name mapped to a role's name or a list of them, granted in the connection's tenant alone.                              |
| `iam.provisioning.groups.resync`  | `null`  | None        | Your re-sync of the groups at a later sign-in, a class implementing `Iam\Contracts\GroupResync`, such as `Iam\Provisioning\MappedGroupResync`; none re-syncs nothing. |

A provisioner bound in the container counts as named, whenever it is bound. Name none and provisioning is off: a
sign-in through SSO that resolves to no identity ends as SSO's `unlinked`. What the provisioner is asked, and in which
transaction, is in [Provisioning and tenancy](provisioning-and-tenancy.md).

A group mapping or re-sync bound in the container counts as named too. The roles the groups map to are granted to the
new identity in the provisioning's transaction, never beyond the connection's tenant; a role that does not exist, or a
mapping that throws, rolls the provisioning back. A value that is no class name, or a map that is no map of group names
to role names, fails closed. Mapping and re-syncing groups is in
[Provisioning and tenancy](provisioning-and-tenancy.md#group-mapping).

## Delivery

| Key                        | Default   | Environment | What it does                                                                       |
|----------------------------|-----------|-------------|------------------------------------------------------------------------------------|
| `iam.delivery.email`       | `null`    | None        | Your email gateway, a class implementing `Iam\Contracts\EmailGateway`.             |
| `iam.delivery.sms`         | `null`    | None        | Your SMS gateway, a class implementing `Iam\Contracts\SmsGateway`.                 |
| `iam.delivery.types.email` | `'email'` | None        | The gateway `laravel-authentication`'s `email` identifier type's codes go through. |
| `iam.delivery.types.phone` | `'sms'`   | None        | The gateway `laravel-authentication`'s `phone` identifier type's codes go through. |

Both gateways are handed the same `Iam\Delivery\CodeMessage`, whichever member issued the code, and your application
writes every message's wording and template. A gateway bound in the container before this package registers counts as
named; one bound after comes too late, so name the gateway here.

- Naming a gateway points MFA's sender of that channel at it.
- `laravel-authentication`'s one-time code sender is pointed at the gateways once every gateway `iam.delivery.types`
  routes to is named. Each entry maps one of `laravel-authentication`'s identifier types to `email` or `sms`.
- Name none and MFA keeps its own senders, which refuse to send (MFA refuses to boot while an application offers `sms`
  or `email` factors with them), and `laravel-authentication`'s one-time code sender stays unbound.

Setting `iam.delivery` in your own file without a `types` key replaces the shipped block one level deep, so it is read
with the shipped `types` (`email` and `phone`). A code for one of MFA's own `email` or `sms` factors goes through
`laravel-authentication` only while its one-time code sender is bound (see
[Authentication and MFA](authentication-and-mfa.md#codes-and-delivery)); otherwise MFA sends it itself. A code MFA
sends itself is delivered inside MFA's transaction; one `laravel-authentication` issues is delivered from its queued
job once the code has committed, and your queue retries it. This package never queues or retries a delivery itself.
See [Testing](testing.md#fakes) for the fake gateways.

## SSO

| Key                | Default | Environment        | What it does                                                                         |
|--------------------|---------|--------------------|--------------------------------------------------------------------------------------|
| `iam.sso.evidence` | `false` | `IAM_SSO_EVIDENCE` | Binds SSO's per-connection evidence policy, `Sso\Evidence\ConnectionEvidencePolicy`. |

`iam.sso.evidence` is read strictly: only `true` (as a boolean or as text, `1`, `on` or `yes`) turns it on. It applies
only while `iam.adapters.sso` is on, and never replaces an evidence policy you bound yourself. The evidence SSO accepts
is only the first of two gates; what it satisfies is MFA's combination policy's to decide. Read
[MFA and SSO](mfa-and-sso.md) before you turn it on.

SSO's own mapping of a provider's attributes (`sso.mapping.custom_attributes`) and its routes are SSO's keys, not this
package's: see [laravel-sso: managing connections][sso-custom-attributes] and
[An example application](example-application.md).

## Audit

| Key                 | Default | Environment         | What it does                                        |
|---------------------|---------|---------------------|-----------------------------------------------------|
| `iam.audit.mappers` | `true`  | `IAM_AUDIT_MAPPERS` | Records the members' events in `laravel-audit-log`. |

`iam.audit.mappers` is read leniently, as the adapter switches are, and as the package boots, so a change takes effect
on the next boot. Turn it off only to map the members' events yourself. Whatever it says, `iam:check` requires every
`jwt` and `api_key` guard excluded from audit-log's own capture (`audit-log.capture.laravel.except_guards`), its Gate
capture off and `audit-log.definitions.require_registered` on; `iam:install` lists the first and the last as owed.

The codes, categories, correlation and the events to alert on are in [The audit trail](audit-trail.md).

## Transactions

| Key                         | Default | Environment                | What it does                                                                 |
|-----------------------------|---------|----------------------------|------------------------------------------------------------------------------|
| `iam.transactions.attempts` | `3`     | `IAM_TRANSACTION_ATTEMPTS` | How many times a change that spans members is attempted, the first included. |

At least 1, read as an integer. A change is retried as a whole when it fails to serialise (SQLSTATE 40001), deadlocks,
meets a lock wait timeout or finds SSO's link candidates changed, and only when the package opened the outermost
transaction: inside a transaction your application opened, the failure is rethrown for you to retry. See
[Operations](operations.md#retries).

```php
use SineMacula\Laravel\Iam\Facades\Iam;

Iam::transaction(function () use ($tenant): void {
    // Write the tenant's new requirement on the storage connection, then report it:
    Iam::tenantPolicies()->changed($tenant);
});
```

## Workers

| Key                 | Default | Environment         | What it does                                                                                                                                                                                                                                        |
|---------------------|---------|---------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `iam.workers.reset` | `true`  | `IAM_WORKERS_RESET` | Flushes every member's request state as each Octane worker starts, before each Octane request and before each queued job not on the `sync` connection, which runs inside the request that dispatched it and keeps its signed-in guards and session. |

Read leniently: `false`, `0`, `off` and `no` turn it off, and any other value leaves it on. Turn it off only when your
application performs the same reset itself. Any other long-lived process calls `Iam::resetWorkerState()` between its
units of work. That reset forgets only the members' and this package's scoped state, never a scoped binding your
application made (over a seam or of its own), so such a loop also calls the container's `forgetScopedInstances()`; see
[Operations](operations.md#workers-and-octane).

[sso-custom-attributes]: https://github.com/sinemacula/laravel-sso/blob/master/docs/guides/managing-connections.md
