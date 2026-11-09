# Authorization

`laravel-authorization` decides what a principal may do: roles, permissions, policies and their evaluation. This
package binds it to the other members: it decides about `laravel-authentication`'s caller, reads its authentication
context, judges a policy's authentication requirements with MFA, answers a refusal for want of a step-up with MFA's
step-up response, caps a machine by its credential's scopes, and answers `laravel-authentication`'s scope registry and
application access from its grants. Some of the glue is still to come: what that leaves to you is in
[What waits](#what-waits).

`laravel-authorization` has no separate guides yet; everything below that is its own is in its
[README][authorization-readme]. How each binding is made, and what replacing it risks, is in
[Bindings](bindings.md#authorization).

- [What is bound](#what-is-bound)
- [The subject](#the-subject)
- [The authentication context](#the-authentication-context)
- [Authentication requirements](#authentication-requirements)
- [Step-up before authorization](#step-up-before-authorization)
- [Machines and their scopes](#machines-and-their-scopes)
- [Access contracts](#access-contracts)
- [Tenants](#tenants)
- [What waits](#what-waits)
- [Its tables](#its-tables)

## What is bound

All of it is bound while `iam.adapters.authorization` is on (see [Configuration](configuration.md#adapters)), and the
requirement checker and the step-up only while `iam.adapters.mfa` is on too.

| `laravel-authorization` asks for              | Answered from                                                                                  |
|-----------------------------------------------|------------------------------------------------------------------------------------------------|
| The subject of a check                        | `Auth::caller()`: the principal, its identity, the active tenant, the application, the session |
| The authentication context                    | `laravel-authentication`'s, with the `mfa` and `sso` namespaces                                |
| Whether a session meets a requirement         | MFA's requirement check, on that session's own proofs                                          |
| A response to a refusal for want of a step-up | MFA's step-up exception, rendered as you render it                                             |
| The scopes that cap a check                   | The scopes of the credential the caller holds                                                  |
| `laravel-authentication`'s scope registry     | `laravel-authorization`'s scope registry                                                       |
| `laravel-authentication`'s application access | The permission `authorization.application_access` maps the application to                      |

`laravel-authorization` binds its own defaults whether or not anything is bound already, so this package replaces them
only while they are still `laravel-authorization`'s defaults. A class you name in its configuration
(`authorization.subject_resolver`, `authorization.requirement_checker`, `authorization.session.source`) is kept, and so
is anything you bind over its contracts in a service provider's `register()` or `boot()`. A binding of one of its
contracts made before `laravel-authorization` registers is lost to its own provider, unless you made it before this
package registered too, when this package binds it back: name your class in its configuration instead. Should
`laravel-authorization` bind its defaults over this package's adapters or your binding once nothing can bind them
back (a provider registering it once the application has booted), `iam:check` refuses each seam it took (see
[Checks](checks.md#seams)).

## The subject

Every check that names no subject (`Authorization::can()`, `authorize()`, the `authorize:` and `permission:` middleware,
the Blade directives) decides about the request's caller, as `Auth::caller()` reads it: its principal, with its
identity, the tenant the request acts in, the guard as the application, and the session it signed in with. A request
with no caller, or a pending session that has not chosen its principal yet, has no subject, and every such check
denies.

Laravel's Gate (`$user->can()`, `@can`, `can:`) hands over `Auth::user()`, the identity. That identity, or the
principal it acts as, is the caller, with its tenant and session, once the default guard has authenticated the request.
Any other principal you hand over (`Gate::forUser($principal)`) is decided about in its own tenant, with no session, so
no authentication requirement is met for it. An identity that is neither the caller's nor a principal itself, and any
other model, is its own subject, in no tenant and with no session, as `laravel-authorization`'s own resolver answers it:
a check about it counts only the grants made to it, never those of a principal it acts as, and a grant made to it
reaches a grant hook as a grant to the identity itself.

A default guard that is not `laravel-authentication`'s (a Laravel session guard an admin panel signs in through, say)
is answered as `laravel-authorization`'s own resolver answers it, except that a `laravel-authentication` principal is
still mapped to the identity it acts for and its own tenant. Which guard happens to be the default never changes what a
principal may do: application access, `authorization:why` and `Gate::forUser($principal)` decide the same on the
grants, denials and boundaries of the principal and its identity, even on a sign-in or refresh route that names no
guard.

## The authentication context

A policy's conditions read `laravel-authentication`'s authentication context, with its own key names:
`authentication.identity_id`, `authentication.principal_id`, `authentication.tenant_id`, `authentication.application`,
`authentication.credential`, `authentication.scopes`, `authentication.ip` and the rest, the `mfa.*` keys MFA's
contributor fills and the `sso.*` keys SSO's fills. Every one of them is declared to `laravel-authorization`'s key
catalogue for you.

Those that say how strongly or how recently the session was authenticated cannot be tested by a condition:
`authentication.amr`, `auth_time`, `mfa`, `recovery_code`, `multifactor` and `seconds_since_step_up`; `mfa.accepted`,
`multifactor`, `factor_types`, `level`, `phishing_resistant`, `user_verification` and
`last_verification_age_seconds`; and `sso.provider_auth_time`, `provider_amr`, `provider_acr` and
`provider_authn_context_class_ref`. State an authentication requirement instead, which is judged on the newest proof
meeting each part. A key you declare yourself in `authorization.context.keys` keeps your declaration.

A namespace your own contributor adds to `Auth::context()` is not part of `laravel-authorization`'s context: supply it
through a context source of your own (`authorization.context.sources`).

**The context is always the request's own caller's.** The `authentication`, `mfa` and `sso` keys describe whoever the
request authenticated as (`laravel-authentication`'s current context, on the default guard), never the subject a check
names. A check about another principal (`Authorization::for($account)`, `Gate::forUser($account)`) is evaluated against
the caller's keys: its `authentication.session_id` and `authentication.credential` are the caller's session and
credential, not anything of `$account`'s. A check made outside any request, as a queued job's is, has no context at
all, so every one of these keys is missing.

## Authentication requirements

A policy statement can require that the session was authenticated strongly enough, and recently enough:

```php
[
    'sid'        => 'refund-after-step-up',
    'effect'     => 'allow',
    'actions'    => ['invoices:refund'],
    'conditions' => [
        'authentication_requirement' => [
            'authentication' => ['multifactor' => ['max_age' => 900]],
        ],
    ],
],
```

MFA judges it, on the proofs `laravel-authentication` recorded for the very session the caller signed in with, as it
judges sign-in, a tenant's requirement and its own route gate: `additional_verification`, `multifactor`,
`phishing_resistant`, and `assurance_level` with a `min` of `aal1`, `aal2` or `aal3`, each within its `max_age`. A
session's reauthentication at its provider is among those proofs, as at MFA's route gate, so where your combination
policy trusts a connection (see [MFA and SSO](mfa-and-sso.md#re-authentication-at-the-provider)), reauthenticating there
renews a `max_age` for a policy statement as it does for a route. Another session's proofs never count, nor do another
person's: a subject you build yourself (a `SineMacula\Laravel\Authorization\Subject` handed to `Authorization::for()`)
whose model is not the identity whose session it names, nor a principal acting for it, or whose tenant is not the
session's, cannot be judged. The tenant is read as `laravel-authorization` reads it, whether it is
`laravel-authentication`'s tenant or `laravel-authorization`'s own reference to it, so `permissionsFor()` in the
caller's scope lists exactly what `can()` allows.

An identity MFA treats as inactive meets no requirement, as at MFA's own route gate: once a person is suspended or
deactivated (or, for an identity `laravel-authentication` cannot deactivate, once its `isMfaActive()` says so), every
part is unmet, whatever its session proved before, so an `authorize:` statement guarded by a requirement and an `mfa:`
route gate give the same answer.

**A subject with no session is never judged.** A machine calling with an API key or a client-credentials token, a
principal you name (`Authorization::for($account)`, `Gate::forUser($account)`) and a queued job's checks have none, and
`laravel-authorization` finds every part of the requirement unmet without asking, so neither an allow nor a deny the
requirement guards applies to them. A deny guarded by a requirement therefore never refuses a subject with no session.

To refuse the caller's own sessionless checks, say so: deny them with a condition on `authentication.credential` or
`authentication.session_id` (a `null` test of `authentication.session_id` holds for a machine on its key or token, and
for a queued job, whose context is empty), or cap a machine by its credential's scopes (see
[Machines and their scopes](#machines-and-their-scopes)). That condition cannot refuse a check about a principal you
name: the context is the caller's (see [The authentication context](#the-authentication-context)), so while the caller
holds a session, a deny on `authentication.session_id` or `authentication.credential` does not apply to
`Authorization::for($account)` or `Gate::forUser($account)`, though `$account` has no session. Nothing in the
authentication context can refuse such a check. For an action guarded by a requirement, either do not name principals
at all, refuse the check in your own code (check the caller's own permission first, say), or deny it with a condition
on a `subject.*` attribute, which describes the subject the check names.

A requirement that cannot be judged for a session makes its test undecidable, so an allow it guards does not apply and
a deny it guards does: a level MFA does not know (`gold`, `AAL2`, `unclassified`), an identity MFA holds no factors for,
a guard that holds no sessions, a key naming no session of the identity's, and another identity's or another tenant's
session.

## Step-up before authorization

When the only thing standing between a request and an allow is an authentication requirement,
`laravel-authorization`'s `authorize()` and its middleware throw its `InsufficientAuthenticationException`. This package
renders it as MFA's `InsufficientAuthenticationException`, asking for the first of its requirements MFA can express,
with the factors MFA offers the caller's session, so you answer one step-up exception, as MFA's
[middleware guide][mfa-middleware-answering] shows, and only MFA produces step-up responses:

```php
// bootstrap/app.php
use SineMacula\Laravel\Mfa\Exceptions\InsufficientAuthenticationException;

->withExceptions(function (Exceptions $exceptions): void {
    $exceptions->render(fn (InsufficientAuthenticationException $exception) => response()->json(
        $exception->toArray(),
        401,
        ['WWW-Authenticate' => $exception->wwwAuthenticate()],
    ));
})
```

A refusal none of whose requirements MFA can express stays Laravel's `403`, and so does a refusal about a subject you
name (`Authorization::for($account)->authorize()`): it was decided on no session, so no step-up by the caller could
ever meet it, and only a refusal decided on the caller's own session asks for one. The rendering is registered on
Laravel's own exception handler; with a handler of your own, map `laravel-authorization`'s exception yourself.

A requirement a whole route has is still MFA's route gate's to state. Put the gate before `laravel-authorization`'s
middleware, so a request that is not signed in strongly enough is answered with a step-up before it can be denied:

```php
Route::middleware(['auth:api', 'mfa:level=aal2', 'authorize:invoices:refund,invoice'])
    ->post('/invoices/{invoice}/refund', RefundInvoice::class);
```

MFA's gate is placed right after authentication in the middleware priority and `authorize:` right after
`SubstituteBindings`, so the two run in that order however a route lists them; `role:` and `permission:` are not
prioritised, so list `mfa` before them. See [Authentication and MFA](authentication-and-mfa.md#one-requirement).

## Machines and their scopes

A machine principal calling with an API key or a client-credentials token is capped by the credential's scopes: a check
is allowed only where the principal's grants allow it and a scope covers it. A scope names a permission or a pattern, or
one `authorization.session.scopes` maps to the actions it stands for; a credential is issued only scopes
`laravel-authorization`'s scope registry accepts, so a typo or a permission that does not exist is refused when the key
is issued or rotated. A key issued no scopes allows nothing. The scopes are read only from the guard holding that very
principal, on the request its credential was admitted on, so a machine checked anywhere else carries no scopes. A
person's session is capped by nothing. A principal the caller names (`Authorization::for($account)`) holds no
credential, so a machine named that way is allowed nothing, as is a machine checked outside its key's request: a queued
job's, or one the Gate is handed on another guard. A machine here is any of `laravel-authentication`'s: a
`MachineIdentity`, or a principal acting for one, whether or not it also implements `laravel-authorization`'s
`SineMacula\Laravel\Authorization\Contracts\AuthorizableMachine`. `laravel-authorization`'s own default source,
`NoSessionPolicy`, allows nothing only to a principal implementing `AuthorizableMachine`, and caps any other machine by
nothing, so with `iam.adapters.authorization` off, bind a session policy source of your own, or name one in
`authorization.session.source`.

The scope registry is `laravel-authorization`'s `CatalogueScopeRegistry` unless you bind
`SineMacula\Laravel\Authorization\Contracts\ScopeRegistry` yourself. It and the session policy source are mandatory
while any guard accepts `api_key` or `client_credentials`: `iam:check` refuses `laravel-authentication`'s
`AcceptAnyScope` and `laravel-authorization`'s `NoSessionPolicy` then, with the switch off too (see
[Checks](checks.md)).

## Access contracts

`laravel-authentication` asks three contracts whether a principal may use an application, act in a tenant and hold the
scopes a credential asks for:

| Contract                                                        | Answered by                                               | What it allows                                                                                                                            |
|-----------------------------------------------------------------|-----------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------|
| `SineMacula\Laravel\Authentication\Contracts\ApplicationAccess` | `laravel-authorization`'s grants                          | an application `authorization.application_access` maps only with the permission it is mapped to; any other application to every principal |
| `SineMacula\Laravel\Authentication\Contracts\ScopeRegistry`     | `laravel-authorization`'s scope registry                  | only scopes naming real permissions                                                                                                       |
| `SineMacula\Laravel\Authentication\Contracts\TenantAccess`      | `laravel-authentication`'s `OwnTenantOnly`, left in place | a principal in its own tenant only                                                                                                        |

Application access is decided in the principal's own tenant, on the application it signs in to, refreshes on or switches
to, and is mandatory while `authorization.application_access` maps an application: `iam:check` refuses
`laravel-authentication`'s `AdmitAnyPrincipal` then. **An application the map does not name is open to every
principal**, people included, whatever their grants: `laravel-authorization` answers `true` for it, and this package
changes nothing of that, nor does `iam:check` warn while the map names any other application. A machine principal is
refused on an application the map names, since it holds no credential yet whose scopes could cap it. So for an
application your machines call, either bind an `ApplicationAccess` of your own that admits the machines and holds
everyone else to their grants, or leave it out of the map and accept that every principal may use it.
Which tenants a principal may act in is your tenancy, not a grant, so bind your own tenant access if your principals act
in other tenants. Your own binding of any of the three, in a service provider's `register()`, is kept. See
`laravel-authentication`'s [extending guide][authentication-extending].

## Tenants

`laravel-authorization` decides in the caller's active tenant, so a role or permission granted inside a tenant counts
there, and a platform-wide one everywhere. It still refuses **no resource for its tenant**: its default resource tenant
resolver, `SineMacula\Laravel\Authorization\Resolvers\NoResourceTenant`, knows no model's tenant, and this package binds
none yet. So a grant in one tenant reaches every tenant's resources: an administrator of one tenant could refund another
tenant's invoice by its id. Until this package names one, do one of these:

- have the models implement `SineMacula\Laravel\Authorization\Contracts\AuthorizableResource`, so a resource names its
  tenant, or bind your own `SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver`;
- or scope every route-bound model to the caller's tenant, so another tenant's resource is never found.

## What waits

| What                                                                                                                                                                   | Until then                                                                                                                                                                                             |
|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| The grant scope query behind SSO's principal scope                                                                                                                     | The principal scope's grant half is `unknown`, so SSO links nobody by a verified domain                                                                                                                |
| The grant hook that calls SSO's scope widening                                                                                                                         | Call `Iam::scopeWidenings()->widen()` yourself, in the grant's transaction                                                                                                                             |
| The tenant tree and `treeChanged()`                                                                                                                                    | Report tree changes to `Authorization::treeChanged()` yourself                                                                                                                                         |
| Invalidating decisions that depended on authentication when MFA confirms, removes or resets a factor, a verification passes or a session returns to pending (IAM-6.11) | Nothing yet: `laravel-authorization` caches grant resolutions, not decisions, and keeps a decision only as the request's last, dropped once its requirement's `metUntil` passes or for another session |
| Mapping a provider's groups to grants at provisioning, and re-syncing them                                                                                             | Your provisioner writes any grant itself                                                                                                                                                               |
| The permission catalogue, and the check for the members' administrative operations                                                                                     | Check every SSO, MFA and audit-log administrative call yourself                                                                                                                                        |
| The audit access policy                                                                                                                                                | Audit-log's `DenyAllPolicy`: every trail read is empty and recorded as denied                                                                                                                          |
| Its events in the audit trail, mapped to codes                                                                                                                         | Recorded by nothing, nor are your own `Gate` checks: audit-log's Gate capture is off (see [The audit trail](audit-trail.md#no-double-records))                                                         |
| `authorization.connection` aligned to `iam.storage.connection`, and checked                                                                                            | Set it yourself (see [Its tables](#its-tables))                                                                                                                                                        |
| `authorization:prune` in `Iam::schedule()`                                                                                                                             | Schedule it yourself, if you rely on it                                                                                                                                                                |
| A resource tenant resolver named by `iam:install`                                                                                                                      | No resource is refused for its tenant (see [Tenants](#tenants))                                                                                                                                        |

`iam:check` already runs `authorization:check`, which reports `laravel-authorization`'s state but always exits `0`, and
the worker reset already forgets its request state between units of work (see
[Operations](operations.md#workers-and-octane)).

What the rows leave to you:

- **A grant that widens a person's reach is not reported to SSO.** No grant hook is bound, so SSO's links in other
  tenants are not suspended when a grant widens a person's scope. Call `Iam::scopeWidenings()->widen()` yourself, inside
  the grant's transaction, for any grant that widens a person's reach, as you do for a membership (see
  [Provisioning and tenancy](provisioning-and-tenancy.md#scope-widening)).
- **The members' administrative operations check no permission.** SSO's connection and domain management, MFA's factor
  administration and audit-log's reads check only what their own guides say; the catalogue of their permissions and the
  helper that checks them do not exist yet. Authorise every such call yourself before you make it.
- **Nobody can read the audit trail.** Audit-log's `SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy` stays
  on its `SineMacula\Laravel\AuditLog\Access\DenyAllPolicy`, so every read through `AuditLog::trail()` comes back
  empty and is recorded as denied. Bind your own policy to let a viewer read what its scope allows; a policy that
  replaces `DenyAllPolicy` decides who reads every person's trail, so a scope too wide (`AccessScope::all()`, or
  `withTenantless()` for a tenant's viewer) shows one tenant's viewer every tenant's people (see
  [The audit trail](audit-trail.md#reading-the-trail)).

## Its tables

`laravel-authorization`'s tables live on `authorization.connection` (`AUTHORIZATION_DB_CONNECTION`), which this package
does not align yet. To grant inside the same transaction as a provisioned membership or any other change that spans
members, put them on the storage connection:

```dotenv
IAM_STORAGE_CONNECTION=mysql
AUTHORIZATION_DB_CONNECTION=mysql
```

## Further reading

- [The authorization design note](../design/authorization.md): how each seam is bound and answered.
- [Provisioning and tenancy](provisioning-and-tenancy.md#principal-scope): why the principal scope waits.
- [The install and check design note](../design/install-and-check.md#what-m11-adds): what the checks gain.

[authorization-readme]: https://github.com/sinemacula/laravel-authorization/blob/master/README.md
[authentication-extending]: https://github.com/sinemacula/laravel-authentication/blob/master/docs/guides/extending.md
[mfa-middleware-answering]: https://github.com/sinemacula/laravel-mfa/blob/master/docs/guides/middleware.md#answering
