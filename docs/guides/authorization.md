# Authorization

`laravel-authorization` decides what a principal may do: roles, permissions, policies and their evaluation. It is
installed with the rest of the suite, but **this package binds nothing of it yet**. The glue between
`laravel-authorization` and the other members waits for seams `laravel-authorization` has still to ship, and lands in
a later release of this package (its milestone M11). Until then `laravel-authorization` runs as it does on its own,
and this guide says plainly what that leaves to you.

`laravel-authorization` has no separate guides yet; everything below that is its own is in its
[README][authorization-readme].

## What is in place now

- **Installed and registered.** `laravel-authorization` is required, and its provider registers with the others.
- **Published.** `iam:install` publishes its configuration, language files and migrations, and offers a prefix for its
  table names while none of its files is published yet (see [Installation](installation.md#prefixing-the-authorization-tables)).
- **Checked.** `iam:check` runs `authorization:check`, which reports its state but always exits `0`, so nothing it
  finds fails the run.
- **Reset between units of work.** The worker reset forgets `laravel-authorization`'s request state (its resolved
  tenant, resolution cache, last decision, evaluator and the rest), and clears the facade roots that would keep it, so
  under Octane, in a queue worker or in a long-running command one request's decisions never reach the next (see
  [Operations](operations.md#workers-and-octane)).
- **No double records.** Audit-log's Gate capture stays off, which `iam:check` enforces, so that once this package maps
  `laravel-authorization`'s decisions they are recorded once.

## What waits

| What                                                                                              | Until then                                                                                                                                     |
|---------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------|
| The subject resolver and the authentication context source                                        | Its own `AuthGuardSubjectResolver`, which knows no `jwt` guard's session                                                                       |
| The requirement checker, answered by MFA's requirement check                                      | Its `RefusingRequirementChecker`: every `authentication_requirement` is unmet                                                                  |
| Mapping its `InsufficientAuthenticationException` to MFA's step-up exception                      | Each is a separate exception, and you answer both                                                                                              |
| `laravel-authentication`'s access contracts: `ApplicationAccess`, `TenantAccess`, `ScopeRegistry` | `laravel-authentication`'s permissive defaults (see [Access contracts](#access-contracts))                                                     |
| The grant scope query behind SSO's principal scope                                                | The principal scope's grant half is `unknown`, so SSO links nobody by a verified domain                                                        |
| Mapping a provider's groups to grants at provisioning, and re-syncing them                        | Your provisioner writes any grant itself                                                                                                       |
| The tenant tree, and invalidating decisions when it or a grant changes                            | Its own tree and caches                                                                                                                        |
| `authorization.connection` aligned to `iam.storage.connection`, and checked                       | Set it yourself (see [Its tables](#its-tables))                                                                                                |
| `authorization:prune` in `Iam::schedule()`                                                        | Schedule it yourself, if you rely on it                                                                                                        |
| Its events in the audit trail                                                                     | Recorded by nothing, nor are your own `Gate` checks: audit-log's Gate capture is off (see [The audit trail](audit-trail.md#no-double-records)) |
| Its subject and resource tenant resolvers named in `iam:install` and required by `iam:check`      | Its own configuration: no tenant on any decision (see [Tenants](#tenants))                                                                     |
| The session policy source, answered from the credential's scopes                                  | Its `NoSessionPolicy`: a machine principal is allowed nothing                                                                                  |
| The grant hook that calls SSO's scope widening                                                    | Call `Iam::scopeWidenings()->widen()` yourself, in the grant's transaction                                                                     |
| The permission catalogue, and the check for the members' administrative operations                | Check every SSO, MFA and audit-log administrative call yourself                                                                                |
| The audit access policy                                                                           | Audit-log's `DenyAllPolicy`: every trail read is empty and recorded as denied                                                                  |

What each of the last four rows leaves to you:

- **A machine principal is denied everything.** `laravel-authorization` caps a check by the credential's scopes
  through its `SineMacula\Laravel\Authorization\Contracts\SessionPolicySource`, and its default,
  `SineMacula\Laravel\Authorization\Resolvers\NoSessionPolicy`, allows a machine principal nothing, so every
  `permission:` or `authorize:` check for an API key fails. Name your own source at `authorization.session.source`,
  built from the scopes `Auth::caller()` holds, if machines call routes `laravel-authorization` guards.
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

## Tenants

Until this lands, `laravel-authorization` decides with **no active tenant**, and refuses **no resource for its
tenant**:

- its default subject resolver, `SineMacula\Laravel\Authorization\Resolvers\AuthGuardSubjectResolver`, decides
  about the user of Laravel's default guard with no tenant active, so only platform-wide grants count. A role or
  permission granted inside a tenant never allows anything;
- its default resource tenant resolver, `SineMacula\Laravel\Authorization\Resolvers\NoResourceTenant`, knows no
  model's tenant, so a model is never refused for being another tenant's.

So `authorize:` and `permission:` give no tenant isolation on their own. If you grant a permission platform-wide to make
it work, every holder may use it on every tenant's resources: an administrator of one tenant could refund another
tenant's invoice by its id. An application with tenants must do one of these until this package binds them:

- bind its own `SineMacula\Laravel\Authorization\Contracts\SubjectResolver`, built from `Auth::caller()` (the
  identity, the principal and the session's tenant), and its own
  `SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver`, or have the models implement
  `SineMacula\Laravel\Authorization\Contracts\AuthorizableResource`, so a resource names its tenant;
- or scope every route-bound model to the caller's tenant itself, so another tenant's resource is never found.

`laravel-authorization`'s README describes the suite as it will be once this lands: its "Under the suite" section
says this package maps `InsufficientAuthenticationException` to MFA's step-up exception, which it does not do yet.

## Step-up before authorization

Because the requirement checker is not bound yet, a policy statement that states an `authentication_requirement`
never allows anything. Require a fresh or stronger session with MFA's route gate instead, and put it before
`laravel-authorization`'s middleware, so a request that is not signed in strongly enough is answered with a step-up
before it can be denied:

```php
Route::middleware(['auth:api', 'mfa:level=aal2', 'authorize:invoices:refund,invoice'])
    ->post('/invoices/{invoice}/refund', RefundInvoice::class);
```

Under `laravel-authorization`'s defaults this route checks a platform-wide grant and nothing of the invoice's tenant
(see [Tenants](#tenants)): bind your own resolvers, or scope the bound invoice to the caller's tenant, before you rely on
it to keep tenants apart.

MFA's gate is placed right after authentication in the middleware priority and `authorize:` right after
`SubstituteBindings`, so the two run in that order however a route lists them; `role:` and `permission:` are not
prioritised, so list `mfa` before them. Answer MFA's `InsufficientAuthenticationException` in your exception handler
(see [Authentication and MFA](authentication-and-mfa.md#one-requirement)).

## Access contracts

`laravel-authentication` asks three contracts whether a principal may use an application, act in a tenant and hold
the scopes a token asks for. This package will answer them from `laravel-authorization`; until then
`laravel-authentication`'s defaults stay bound, and they are permissive:

| Contract                                                        | Default             | What it allows                     |
|-----------------------------------------------------------------|---------------------|------------------------------------|
| `SineMacula\Laravel\Authentication\Contracts\ApplicationAccess` | `AdmitAnyPrincipal` | any principal, on any application  |
| `SineMacula\Laravel\Authentication\Contracts\TenantAccess`      | `OwnTenantOnly`     | a principal in its own tenant only |
| `SineMacula\Laravel\Authentication\Contracts\ScopeRegistry`     | `AcceptAnyScope`    | any scope a token asks for         |

Bind your own wherever those answers are too wide for your application, in a service provider's `register()`; your
binding is kept when this package starts answering them. See `laravel-authentication`'s
[extending guide][authentication-extending].

## Its tables

`laravel-authorization`'s tables live on `authorization.connection` (`AUTHORIZATION_DB_CONNECTION`), which this package
does not align yet. To grant inside the same transaction as a provisioned membership or any other change that spans
members, put them on the storage connection:

```dotenv
IAM_STORAGE_CONNECTION=mysql
AUTHORIZATION_DB_CONNECTION=mysql
```

## Further reading

- [Provisioning and tenancy](provisioning-and-tenancy.md#principal-scope): why the principal scope waits.
- [The install and check design note](../design/install-and-check.md#what-m11-adds): what the checks gain.

[authorization-readme]: https://github.com/sinemacula/laravel-authorization/blob/master/README.md
[authentication-extending]: https://github.com/sinemacula/laravel-authentication/blob/master/docs/guides/extending.md
