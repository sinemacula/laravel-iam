# The Audit Trail

`laravel-audit-log` records security-relevant activity and decides how it is stored, sealed, kept and read. This
package describes the other members' events to it: one mapper per member, a definition for every code they record, a
contributor that fills a record's gaps from the caller, and the settings that keep anything from being recorded twice.
It records nothing of its own, and enforces nothing through events.

How audit-log stores, reads and keeps records is in its guides: [events][audit-events],
[automatic capture][audit-capture], [reading][audit-reading], [retention][audit-retention] and
[operations][audit-operations]. Each member's own events are in its events guide.

## What is recorded

While `iam.audit.mappers` (`IAM_AUDIT_MAPPERS`) is on, the default, every event of `laravel-authentication`, MFA, SSO
and `laravel-authorization` is recorded through one mapper per member:

| Member events                                      | Mapper                                                           |
|----------------------------------------------------|------------------------------------------------------------------|
| `laravel-authentication`'s (`AuthenticationEvent`) | `SineMacula\Laravel\Iam\Audit\Mappers\AuthenticationEventMapper` |
| MFA's (`MfaEvent`)                                 | `SineMacula\Laravel\Iam\Audit\Mappers\MfaEventMapper`            |
| SSO's (`SsoEvent`)                                 | `SineMacula\Laravel\Iam\Audit\Mappers\SsoEventMapper`            |
| `laravel-authorization`'s (`AuthorizationEvent`)   | `SineMacula\Laravel\Iam\Audit\Mappers\AuthorizationEventMapper`  |

A mapper reads only the event, its context and the morph map, never the request or the current user. A bind's noise
(`PrincipalAssigned`, `SessionAuthenticated`) and a refresh's `SignedIn`, which repeats the `Refreshed` beside it, are
skipped. Every other pair the members report is two facts and is recorded once each, such as a sign-in's
`session.created` and `authentication.signed_in`. Of `laravel-authorization`'s decisions only those worth a record are
recorded (see [Authorization decisions](#authorization-decisions)).

The registrations are made while the application boots, before audit-log stops taking them, so a change to the switch
takes effect on the next boot: a deploy or a worker restart. Turn it off (`false`, `0`, `off`, `no`) only to map the
members' events yourself.

## Codes

Where a member's event means what one of audit-log's own codes means, that code is reused unchanged, so one query
answers across guards:

| Event                                              | Code                            |
|----------------------------------------------------|---------------------------------|
| A sign-in                                          | `authentication.signed_in`      |
| A refused sign-in                                  | `authentication.sign_in_failed` |
| A sign-in refused because its attempts are used up | `authentication.locked_out`     |
| A person's own sign-out                            | `authentication.signed_out`     |
| An email address verified                          | `account.email_verified`        |
| A password reset                                   | `account.password_reset`        |

Everything else has a code of its own, under its member's prefix, defined by the package's code enums
(`SineMacula\Laravel\Iam\Audit\Enums\AuthenticationActivity`, `SessionActivity`, `MfaActivity`, `SsoActivity` and
`AuthorizationActivity`):

- **`authentication.*`** (25 codes): refusals by flow (`authentication.request_rejected`,
  `authentication.api_key_rejected`, and `authentication.{flow}_failed` for client credentials, code requests,
  identifier verification, password resets, identifier changes, factor codes and password changes), a sign-in refused
  for a concealed reason (`authentication.sign_in_failed_concealed`), SSO's redemption halves
  (`authentication.external_result_redeemed`, `authentication.external_result_unlinked`), identifier and password
  changes, passkeys, API keys and client credentials.
- **`session.*`** (16 codes): a session created, pending, activated or returned to pending, revoked, every session
  ended together (`session.signed_out_everywhere`), refreshed, switched, stepped up and reauthenticated, and each of
  those refused (`session.{flow}_failed`, `session.factor_recheck_failed`).
- **`mfa.*`** (21 codes): codes sent, enrolments, factors confirmed, disabled, enabled again, removed, renamed and
  reset, lockouts, recovery codes, and every verification passed or failed. A factor enabled again
  (`mfa.factor_enabled`) is recorded as the act of whoever `Mfa::enableFactor()` names, on the person, keeping the
  factor's id and type as a lockout lifted (`mfa.lockout_lifted`) does.
- **`sso.*`** (34 codes): a flow's stages and its failure (`sso.flow_failed`, keeping its flow), links, connections,
  domains, enforcement and exemptions, keys, and metadata and key set refreshes.
- **`authorization.*`** (29 codes): a check denied (`authorization.access_denied`, keeping the action, the resource,
  the application and the deciding statements, with the decision's reason code), allowed by a break-glass grant
  (`authorization.break_glass_used`) or previewed for another principal (`authorization.access_previewed`); roles,
  permissions and policies created, updated and deleted; a permission granted to or revoked from a role; a role,
  permission or policy assigned to or taken from a grantee; boundaries and guardrails set and removed; a grant expired
  or its expiry changed; a policy attached to or detached from a resource; and a protected record changed by a system
  override. None is audit-log's `authorization.gate_denied`, whose capture stays off.

Every definition is version 1 and keeps only the properties it lists. Nothing kept is a secret or free text: a factor
by its id and type, never its label or destination; a policy by its document's version and digest, never the document,
and an update by the names of the fields it changed, never their values; reasons as codes; an identifier change's
identifiers pseudonymised under audit-log's redaction key. Every code's definition is registered, so turn audit-log's
`definitions.require_registered` on, which `iam:install` writes and `iam:check` requires: a code with no definition is
then refused rather than recorded unchecked.

**Your own codes need definitions too.** Once `definitions.require_registered` is on, every code your application
records must have a definition registered with `AuditLog::define()` before it is recorded, from a service provider's
`boot()`; recording a code with none throws an `InvalidArgumentException` saying it is not registered. A code your
application recorded under audit-log's permissive default, before the setting was turned on, is refused from then on.
Define each as laravel-audit-log's [extending guide][audit-extending] describes, by an enum implementing
`SineMacula\Laravel\AuditLog\Contracts\DefinesAuditEvents` or one at a time:

```php
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;

// A service provider's boot()
AuditLog::define(EventDefinition::for('orders.shipped')->category('orders'));
```

## Categories

Every code is in the `security` category, except SSO's administration (connections created, changed, enabled, disabled
and deleted; domains claimed, verified, rechecked, restored, lapsed and removed; enforcement changed; keys added, made
current and retired) and every change `laravel-authorization` makes (its roles, permissions, policies, grants,
boundaries and guardrails), which are in `access_management`: a change to who may sign in, or do what, which you may
keep longer than routine denials. `laravel-authorization`'s decisions are in `security`, and audit-log's own records of
who read the trail in `audit`. Set each category's retention in audit-log (see its [retention guide][audit-retention]).

## Correlation

Each record carries one correlation id, the first of these that applies:

| Correlated as                             | Records                                                                             |
|-------------------------------------------|-------------------------------------------------------------------------------------|
| `sso:{connection_id}:{request_reference}` | every SSO event of one sign-in, and `laravel-authentication`'s redemption events    |
| `mfa:{challenge}`                         | MFA's code and verification events, and a refused factor code naming that challenge |
| `authentication:{challenge}`              | `laravel-authentication`'s own code challenges                                      |
| `session:{session_id}`                    | everything else about a session                                                     |
| `authorization:{operation_id}`            | every change of one `laravel-authorization` management call                         |

A missing part means no id, and an id longer than 191 bytes is none, so correlation never loses a record. So an SSO
sign-in reads as `sso.authorization_request_started`, `sso.result_verified`, `sso.handoff_issued` and
`sso.handoff_redeemed`, correlated as the SSO sign-in, then `session.created` and `authentication.signed_in`,
correlated by the new session, and `authentication.external_result_redeemed`, correlated with SSO's halves and naming
the session.

## Who did it

- A record of what a person did for themselves (a sign-in, a verification) names them as the actor.
- A refusal, whose author was never proven, and what a member did by itself (a lockout applied, a key nearing expiry)
  name explicitly no one.
- What the event does not say who did (a revocation, a passkey removed) is left to the caller: the package's context
  contributor fills the actor, guard, principal, tenant and session from what a `jwt` or `api_key` guard already holds,
  never authenticating anything to find out.
- An operator the event names (MFA's actor, SSO's acting identity) is the actor.
- A `laravel-authorization` change is the call's: the identity behind the acting principal, as that principal; the
  reference a trusted console command names; or explicitly no one for system work (a grant the pruner found expired,
  a write through a model outside its services), never the request's caller. A decision is the subject's it was made
  about, and a preview the previewer's, about the principal previewed.

Your own records get the same: `AuditLog::record('orders.shipped')`, its code defined as [Codes](#codes) shows, on a
bearer request names the caller the guard holds. A queued job carries the caller who dispatched it, so the records it
leaves to the caller name that person.

## Refusals inside a transaction

`laravel-authentication` reports a refusal at once, from inside whatever transaction is open, and several roll back on
purpose once it has refused: a refused SSO redemption, so the code stays unspent; a refused step-up or pending
completion inside MFA's transaction; a transaction of your own. `laravel-authorization` reports each decision the same
way, as it is made. A refusal, or a decision recorded, reported while a transaction is open on audit-log's storage
connection is held and recorded once the outermost transaction there has ended, whichever way it ended, so it is
recorded once and never lost with the rollback. Every other record is written at once, and is durable
only once any transaction around it commits.

## No double records

`laravel-authentication`'s `jwt` guard dispatches Laravel's `Login`, `Failed` and `Logout` beside its own events, and
audit-log's own capture of Laravel's events would record each a second time. So:

- every `jwt` and `api_key` guard is listed in `audit-log.capture.laravel.except_guards`;
- audit-log's Gate capture stays off (`audit-log.capture.gate.enabled`), so that each authorization decision is
  recorded once, through `laravel-authorization`'s own events.

`iam:install` writes the exclusions into a `config/audit-log.php` it publishes, and `iam:check` refuses a configuration
without either, whatever `iam.audit.mappers` says. Add every guard you declare later to the list yourself. Two
consequences of the exclusion: a sign-in made through a `jwt` guard's own `attempt()` or `login()`, rather than the
session service, dispatches only `Login`, and is recorded by nothing; nor is an `api_key` guard's `logout()`. Sign
people in through `Auth::sessions()`.

## Authorization decisions

`laravel-authorization` reports every check it decides, allows included, and a denial `authorize()` throws a second
time (`AuthorizationFailed`). The mapper records:

- a denial, once, as `authorization.access_denied`, denied with `laravel-authorization`'s reason code (`no_match`,
  `tenant_scope`, `explicit_deny` and the rest), whether it came from `can()`, `check()`, `authorize()`, the Gate or
  your own `Gate` checks, since `laravel-authorization` answers the Gate;
- a check a break-glass grant allowed, as `authorization.break_glass_used`;
- a preview, as `authorization.access_previewed`, by the previewer, about the principal previewed, whatever it decided.

It records no other allow. A denial as `insufficient_authentication` is recorded as `authorization.access_denied` too,
denied with that reason: on a request's own session it asks for a stronger proof, and MFA's step-up records what
follows, but a check made on no session, a job's or a command's, can never be stepped up, so the denial is the only
record of the refusal. Filter on the reason to tell step-up prompts apart from other denials. A role, permission or
policy deleted with grants still held carries every grantee as its manifest, as audit-log's bulk record does, so the
bound store must keep attachments, as audit-log's own stores do; a store that keeps none fails the record, reported as
`AuditCaptureFailed`.

Each `authorization.*` record is filed under the tenant `laravel-authorization` names, by its identifier, which is its
key: a tenant whose key does not resolve back to it through `laravel-authentication`'s
[tenant resolver](provisioning-and-tenancy.md#the-tenant-resolver) (keyed otherwise than by its identifier) is
recorded with no tenant, which no viewer scoped to tenants reads, rather than under its key, which could be another
tenant's identifier.

## Operational alerts

The suite's operational events can reach your alerting. Name a listener class, or a list of them, for each:

```php
// config/iam.php
'audit' => [
    'alerts' => [
        'audit_write_failed'     => [App\Alerts\NotifyOperators::class],
        'audit_capture_failed'   => [App\Alerts\NotifyOperators::class],
        'integrity_check_failed' => [App\Alerts\PageOnCall::class],
        'key_nearing_expiry'     => [App\Alerts\NotifyOperators::class],
    ],
],
```

| Key                      | Event                              | When                                                          |
|--------------------------|------------------------------------|---------------------------------------------------------------|
| `audit_write_failed`     | audit-log's `AuditWriteFailed`     | a record could not be written                                 |
| `audit_capture_failed`   | audit-log's `AuditCaptureFailed`   | an event a mapper could not describe                          |
| `integrity_check_failed` | audit-log's `IntegrityCheckFailed` | sealing or verification found the log altered or unverifiable |
| `key_nearing_expiry`     | SSO's `KeyNearingExpiry`           | a key or certificate is within a threshold of its end         |

Each listener is resolved from the container and handed the event through its `handle()` method, or invoked,
synchronously, in the order named. With none named nobody is told: the package sends nothing itself. Alert by other
means than the audit log (a notification, a log channel): a record a listener makes of a write failure is refused,
and one it makes of an integrity failure goes into the very log just found altered. `iam:check` refuses a value that
names no listener.

## Reading the trail

Nothing in this package reads the trail. Audit-log's `SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy` is
answered from `laravel-authorization`'s grants (`SineMacula\Laravel\Iam\Authorization\AuditAccessPolicyAdapter`), while
`iam.adapters.authorization` is on, of the permissions in this package's catalogue (see
[Authorization](authorization.md#administrative-operations-and-the-trail)). Each read purpose has its own permissions,
so a viewer may page through the trail and be denied export:

| Permission                       | Reaches                                                                       |
|----------------------------------|-------------------------------------------------------------------------------|
| `audit-log.{purpose}`            | every category, where it is granted                                           |
| `audit-log.{purpose}.{category}` | one of the suite's categories (`security`, `access_management`, `audit`)      |
| `audit-log.{purpose}.own`        | only the viewer's own activity, as the actor or the subject of a record       |

`{purpose}` is `read`, `count`, `export` or `verify`. The grants become one scope, never wider than any of them:

- the tenants it holds the purpose in, among its own tenant and the tenants your memberships say it belongs to, in the
  categories every one of those tenants allows, so tenants whose grants share no category see nothing; a principal
  counts its own grants in a membership tenant only where your `TenantAccess` lets it act there, and elsewhere only its
  identity's grants;
- otherwise, its own activity in the tenants it holds `.own` in;
- otherwise nothing.

Each tenant is decided as a check there would be, so a platform-wide grant counts in every one of those tenants, but a
tenant whose own policies deny the purpose is left out. A grant never shows the whole trail: no viewer sees records
with no tenant, which may be about any tenant's people, and a viewer with no tenant of its own and no membership sees
nothing, whatever it is granted platform-wide. Grants in more tenants than audit-log's scope holds (100) refuse the
read rather than show some of them.

Audit-log tells the policy who is reading and why, never how they signed in or how recently. A requirement on the
authentication itself, such as a fresh multi-factor check, belongs on the route or action that reads the trail,
enforced before `visibleTo()` is called, with MFA's route gate (`mfa:level=aal2`, see
[Authorization](authorization.md)) for instance. The policy cannot tell whether such a requirement is met, so it treats
a permission an authentication requirement guards as not held in the tenant where it guards it, whether the
requirement is on the allow or on a deny: put freshness on the route, never on the `audit-log.*` grants. This holds
under this package's requirement checker; one of your own should refuse, by throwing, a subject whose session it cannot
find, or a deny a requirement guards stops applying to the policy's reads.

Bind your own policy in a service provider's `register()` to decide otherwise, as reading the whole platform's trail
needs; it is kept ([laravel-audit-log: reading][audit-reading]).

This package records every tenant, on the members' records and on your own records made on a bearer request, as
`Reference::of('tenant', $tenant->getTenantIdentifier())` (`Iam\Audit\References::TENANT_TYPE`): the opaque tenant
identifier under the one type `tenant`, never a model's morph class. `AccessScope::tenants()` matches the type and the
identifier together, so scope a tenant's viewer with
`SineMacula\Laravel\AuditLog\Access\AccessScope::tenants(Reference::of('tenant', $tenantId))`, where `Reference` is
`SineMacula\Laravel\AuditLog\Records\Reference`; a scope built with `Reference::to($organisation)`, as a policy over
your own models would, matches none of these records, and every read comes back empty. Do not widen the policy to make
it read something. A record whose event names no tenant and whose caller acts in none carries no tenant: a sign-in, and
a refusal, before a tenant is chosen, a platform principal's activity, and what a command or job does for no tenant.
`withTenantless()` shows a viewer every such record, of every tenant's people, and `AccessScope::all()` shows every
tenant's trail: grant either only to a viewer trusted with the whole platform.

Inside `Iam::transaction()` audit-log refuses a read while it stores on the
storage connection (`AuditReadRefusedException`, `in_transaction`), since the read, or a row it would show, could
still roll back: read after the commit. With audit-log on a connection of its own the read is let in, and reads only
what has committed there; `iam:check` notes that set-up.

## Further reading

- [The audit mapping design note](../design/audit-mapping.md): every mapping rule, sequence and gap.
- [Operations](operations.md#secrets-and-key-rotation): audit-log's keys among the suite's.

[audit-events]: https://github.com/sinemacula/laravel-audit-log/blob/master/docs/guides/events.md
[audit-extending]: https://github.com/sinemacula/laravel-audit-log/blob/master/docs/guides/extending.md
[audit-capture]: https://github.com/sinemacula/laravel-audit-log/blob/master/docs/guides/automatic-capture.md
[audit-reading]: https://github.com/sinemacula/laravel-audit-log/blob/master/docs/guides/reading.md
[audit-retention]: https://github.com/sinemacula/laravel-audit-log/blob/master/docs/guides/retention.md
[audit-operations]: https://github.com/sinemacula/laravel-audit-log/blob/master/docs/guides/operations.md
