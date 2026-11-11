# Authorization

`laravel-authorization` decides what a principal may do: roles, permissions, policies and their evaluation. This
package binds it to the other members: it decides about `laravel-authentication`'s caller, reads its authentication
context, judges a policy's authentication requirements with MFA, answers a refusal for want of a step-up with MFA's
step-up response, caps a machine by its credential's scopes, and answers `laravel-authentication`'s scope registry and
application access from its grants. It reports a grant that widens a person's reach to SSO, answers the grant half of
SSO's principal scope, hands it your tenant tree and its changes, forgets the decision it keeps once the authentication
that decision read changes, answers audit-log's access policy from its grants, offers a catalogue of the members'
administrative permissions, maps its events into the audit trail, and keeps its tables on the storage connection.

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
- [Grants, the tree and SSO](#grants-the-tree-and-sso)
- [Decisions after authentication changes](#decisions-after-authentication-changes)
- [Administrative operations and the trail](#administrative-operations-and-the-trail)
- [Its tables](#its-tables)
- [Pruning and checks](#pruning-and-checks)

## What is bound

All of it is bound while `iam.adapters.authorization` is on (see [Configuration](configuration.md#adapters)), the
requirement checker and the step-up only while `iam.adapters.mfa` is on too, and the grant hook only while
`iam.adapters.sso` is on too.

| `laravel-authorization` asks for              | Answered from                                                                                  |
|-----------------------------------------------|------------------------------------------------------------------------------------------------|
| The subject of a check                        | `Auth::caller()`: the principal, its identity, the active tenant, the application, the session |
| The authentication context                    | `laravel-authentication`'s, with the `mfa` and `sso` namespaces                                |
| Whether a session meets a requirement         | MFA's requirement check, on that session's own proofs                                          |
| A response to a refusal for want of a step-up | MFA's step-up exception, rendered as you render it                                             |
| The scopes that cap a check                   | The scopes of the credential the caller holds                                                  |
| `laravel-authentication`'s scope registry     | `laravel-authorization`'s scope registry                                                       |
| `laravel-authentication`'s application access | The permission `authorization.application_access` maps the application to                      |
| The principals an identity owns               | `laravel-authentication`'s principals of that identity                                         |
| The tenant tree                               | Your `SineMacula\Laravel\Iam\Contracts\TenantTree`, or its own flat tree without one           |
| The grant hook                                | SSO's scope widening, after the hooks `authorization.grant_hooks` lists                        |
| Audit-log's access policy                     | The catalogue's audit permissions the viewer holds                                             |

`laravel-authorization` binds its own defaults only where nothing is bound yet, so this package replaces them only
while they are still `laravel-authorization`'s defaults, in whatever order the providers register. A class you name in
its configuration (`authorization.subject_resolver`, `authorization.requirement_checker`,
`authorization.session.source`, `authorization.identity_directory`, `authorization.tenant_tree`) is kept, and so is
anything you bind over its contracts in a service provider's `register()` or `boot()`, before `laravel-authorization`
registers or after. Hooks you list in `authorization.grant_hooks` are not a class of their own: the grant hook is bound
over the default whatever you list, and `laravel-authorization` runs your hooks before it, so before SSO's widening.

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

A default guard that is not `laravel-authentication`'s (a Laravel session guard an admin panel signs in through, say) is
answered as `laravel-authorization`'s own resolver answers it, except that a `laravel-authentication` principal is still
mapped to the identity it acts for and its own tenant. A person signed in there with the Laravel session is capped by
nothing, and a machine signed in that way is allowed nothing, as a machine with no credential of its own is. Which guard
happens to be the default never changes what a principal may do: application access, `authorization:why` and
`Gate::forUser($principal)` decide the same on the grants, denials and boundaries of the principal and its identity,
even on a sign-in or refresh route that names no guard.

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
ever meet it, and only a refusal decided on the caller's own session asks for one. Either way the refusal is recorded
as `authorization.access_denied`, denied with `insufficient_authentication` (see
[The audit trail](audit-trail.md#authorization-decisions)). The rendering is registered on
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
is issued or rotated. A key issued no scopes allows nothing. The scopes travel on the subject: the subject resolver says
what the caller's credential carries on the request's subject (`SineMacula\Laravel\Authorization\Subject::$scopes`,
a `CredentialScopes`), and on the subject the Gate decides about when it is the caller, and the session policy source
caps every check about that subject by them. A person's session is capped by nothing. A principal the caller names
(`Authorization::for($account)`) holds no credential, so a machine named that way is allowed nothing, as is a machine
checked outside its key's request: a queued job's, or one the Gate is handed on another guard.

A `Subject` you build yourself that says nothing of its scopes fails closed wherever it names a credential the source
cannot establish:

- naming a session, it carries no cap while that is a live session of the guard it names, owned by the identity it
  acts for, and is allowed nothing otherwise (a revoked session, another identity's, one of another guard, or a key
  that names none);
- naming a guard whose caller it is, it is capped by that caller's credential, as the request's own subject is;
- naming a guard that is not configured, it is allowed nothing;
- naming no credential, as a job's or a console command's subject, or naming a guard whose caller is someone else, it
  carries no cap if it is a person and is allowed nothing if it is a machine.

Say the scopes yourself (`scopes: CredentialScopes::of([...])` or `CredentialScopes::uncapped()`, from
`SineMacula\Laravel\Authorization\Support\CredentialScopes`) when you know them.

A machine here is any of `laravel-authentication`'s: a `MachineIdentity`, or a principal acting for one, whether or not
it also implements `laravel-authorization`'s `SineMacula\Laravel\Authorization\Contracts\AuthorizableMachine`.
`laravel-authorization`'s own default source, `NoSessionPolicy`, allows nothing only to a principal implementing
`AuthorizableMachine`, and caps any other machine by nothing, so with `iam.adapters.authorization` off, bind a session
policy source of your own, or name one in `authorization.session.source`.

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
admitted on its grants as a person is: admission is decided without the caps of a credential's scopes, since the
principal being admitted holds no session yet, while a deny, a boundary or a guardrail still refuses it.
Which tenants a principal may act in is your tenancy, not a grant, so bind your own tenant access if your principals act
in other tenants. Your own binding of any of the three, in a service provider's `register()`, is kept. See
`laravel-authentication`'s [extending guide][authentication-extending].

## Tenants

`laravel-authorization` decides in the caller's active tenant, so a role or permission granted inside a tenant counts
there, and a platform-wide one everywhere. It refuses a record of another tenant (`tenant_scope`) only where it knows
the record's tenant. It still refuses **no resource for its tenant** unless you tell it which tenant owns each record:
its default resource tenant resolver, `SineMacula\Laravel\Authorization\Resolvers\NoResourceTenant`, knows no model's
tenant, and which tenant owns a record is your rule, on your models, so this package binds none. Without one of these, a
grant in one tenant reaches every tenant's resources: an administrator of one tenant could refund another tenant's
invoice by its id.

- have the models declare their tenancy (`SineMacula\Laravel\Authorization\Contracts\QueryableResource`) or name their
  tenant (`SineMacula\Laravel\Authorization\Contracts\AuthorizableResource`);
- name your own `SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver` in
  `authorization.resource_tenant_resolver`, or bind the contract yourself;
- or scope every route-bound model to the caller's tenant, so another tenant's resource is never found.

While your memberships are bound or named, `iam:check` notes the default resolver left in place (see
[Checks](checks.md#configuration)). It cannot see your models, so it only notes it.

## Grants, the tree and SSO

These are bound while `iam.adapters.authorization` is on, and those that report to SSO only while `iam.adapters.sso` is
on too (see [Bindings](bindings.md#authorization)).

- **A grant that widens a person's reach is reported to SSO first.** `laravel-authorization`'s grant hook is answered by
  SSO's scope widening, inside the grant's own transaction: a grant to a person, or to a principal they own, that
  reaches beyond what they held (another tenant, the platform, a subtree) suspends their SSO links in every other
  tenant before it is written, and a refusal rolls the grant back. Grant hooks you list in
  `authorization.grant_hooks` still run, before SSO's. A grant to a grantee that is not `laravel-authentication`'s
  identity (an admin panel's user on a Laravel session guard, say) is not reported to SSO, which never links one, and
  its tenants are not resolved; your listed hooks still run for it. See
  [Provisioning and tenancy](provisioning-and-tenancy.md#scope-widening). Each tenant such a grant holds in is named
  to SSO through `laravel-authentication`'s tenant resolver, so bind one (see
  [The tenant resolver](provisioning-and-tenancy.md#the-tenant-resolver)): a grant to the person always widens, and so
  does a principal's first grant in a tenant, so under the default `ResolveNoTenant` every such grant in a tenant is
  refused, and `iam:check` refuses that default while both adapters are on. When one of the person's links by a
  verified domain is committed while the grant runs, SSO refuses the widening, and the hook hands the refusal on as a
  concurrency error (SQLSTATE `40001`): `laravel-authorization` tries a delegated grant again by itself, but never a
  trusted one, so make a trusted grant inside `Iam::transaction()` (or `DB::transaction()` given attempts) to have it
  tried again rather than refused.
- **The grant half of SSO's principal scope** is answered by `laravel-authorization`'s grant scope query, over the
  principals `laravel-authentication` lists for the identity (its `principals()` relation, global scopes set aside;
  `unknown` for an identity that is neither a principal nor owns principals), and combined with the membership half: a
  person is within a tenant only when both halves say so, and outside when either does (see [Provisioning and
  tenancy](provisioning-and-tenancy.md#principal-scope)).
- **One tenant tree.** `laravel-authorization`'s tenant tree is your `SineMacula\Laravel\Iam\Contracts\TenantTree`, so a
  grant on a tenant with its subtree reaches the tenants your tree puts below it, and a tree change you report with
  `Iam::treeChanges()->changed()` reaches `laravel-authorization` too. Keep the tree on the storage connection, so
  the grant scope query can read it. Your subtree may select its ids as integers: they are compared as text. Every
  tenant of the tree must be of one type: a tree placing a tenant below one of another type is refused (see
  [Provisioning and tenancy](provisioning-and-tenancy.md#the-tenant-tree)). While you
  name or bind no tree, `laravel-authorization` keeps its own flat tree, which it scopes `whereAuthorized()` by a
  record's tenant column alone, whichever connection the record is on. With a tree, every tenant
  `laravel-authorization` asks about resolves through `laravel-authentication`'s tenant resolver, so bind one (see
  [The tenant resolver](provisioning-and-tenancy.md#the-tenant-resolver)); `iam:check` refuses the default then.
- **A move reports the people granted below it.** A grant rooted below a tenant counts within it, so moving that
  subtree out from under the tenant takes the person's grant beyond it with no grant written. While both adapters are
  on, `Iam::treeChanges()->changed()` reports everyone holding a live grant in the moved subtree to SSO's scope
  widening, in the move's transaction, which suspends their links by a verified domain in every other tenant and
  revokes the sessions established through them (see
  [Provisioning and tenancy](provisioning-and-tenancy.md#the-tenant-tree)). It takes every one of their SSO identity
  guards first, in SSO's lock order, so a grant, reservation or activation of one of them made at the same time waits
  for the move, or the move for it, and neither is aborted for a deadlock.
- **Group mapping.** A provider's groups map to grants at provisioning, and, where you opt in, again at each later
  sign-in, once the sign-in commits (see [Provisioning and tenancy](provisioning-and-tenancy.md)).

## Decisions after authentication changes

`laravel-authorization` decides every check afresh, on the session's proofs as they are, so a check made after a step-up
or a removed factor reads the change. The one decision it keeps is the request's last, which
`Authorization::lastDecision()` returns and an exception handler reads to explain a refusal. When MFA confirms or
removes a factor, registers a passkey, resets a person's factors, passes a verification or returns a session to
pending, this package forgets that last decision if it read an authentication requirement in that session or about
that person, so it never explains a refusal, or an allow, the session's proofs no longer support. A decision made in a
transaction that rolls back afterwards is forgotten again, including when MFA's change was made in a savepoint of a
transaction of yours that rolls back once the savepoint has committed. There is nothing else to invalidate: no decision
is cached across checks.

## Administrative operations and the trail

- **Administrative operations.** The members authorise none of their administrative operations themselves: SSO's
  connection, key, domain, enforcement and link management, MFA's resets, unlocks, re-enabling and erasure, and reads
  of the audit trail. This package ships a catalogue of their permissions,
  `SineMacula\Laravel\Iam\Authorization\PermissionCatalogue`, which you opt into by naming it in
  `authorization.permission_providers` and running `authorization:sync`. Its names are
  `SineMacula\Laravel\Iam\Authorization\Enums\AdministrativeOperation`'s cases: SSO's own operation names where SSO
  has one (`sso.connection.trust`, `sso.domain.verify`, `sso.link.remove` and the rest), and names of this package's
  where neither member names one (`sso.connection.create`, `sso.keys.trust_certificate`, `sso.link.remove_others`,
  `mfa.identity.reset`, `mfa.factor.unlock`, `mfa.factor.enable`, `mfa.identity.erase`, and `mfa.requirements.manage`
  for your own screens over your requirement contracts). Removing someone else's link is a permission of its own.
  Re-enabling a factor disabled at its ceiling (`SineMacula\Laravel\Mfa\Facades\Mfa::enableFactor()`, which names
  its actor) is `mfa.factor.enable`.
- **Checking one.** Before the call, check it with
  `SineMacula\Laravel\Iam\Authorization\AdministrativeCheck::authorize()`, handing it the subject, the operation and
  the member's object: its type, its id (`null` for an operation on the type, such as creating a connection) and its
  tenant's identifier. The subject is a resolved `SineMacula\Laravel\Authorization\Subject`, never a bare model: hand
  it the request's subject (`Authorization::currentSubject()`), which carries the session, so an authentication
  requirement on the operation is judged against that session's proofs, or one you build for a job or a command. It is
  decided in the tenant and application it names, or on the platform when it names no tenant, whatever tenant the
  request is in, and the request's scope is in place again afterwards. The object's tenant is
  resolved through `laravel-authentication`'s [tenant resolver](provisioning-and-tenancy.md#the-tenant-resolver), so
  an object in a tenant needs one bound. A denial throws
  `laravel-authorization`'s `AuthorizationException`, or MFA's step-up exception for want of a stronger proof, before
  anything is changed, and is recorded as `authorization.access_denied`:

  ```php
  use Illuminate\Auth\AuthenticationException;
  use SineMacula\Laravel\Authorization\Facades\Authorization;
  use SineMacula\Laravel\Iam\Authorization\AdministrativeCheck;
  use SineMacula\Laravel\Iam\Authorization\Enums\AdministrativeOperation;

  app(AdministrativeCheck::class)->authorize(
      Authorization::currentSubject() ?? throw new AuthenticationException,
      AdministrativeOperation::SSO_CONNECTION_TRUST,
      'sso_connection',
      $connectionId,
      $tenantId,
  );
  ```

  A grant counts for an object of the tenant the subject acts in, or of one below it; an object of any other tenant is
  refused unless a platform-wide grant admits it.
- **Reading the audit trail.** Audit-log's `SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy` is answered from
  `laravel-authorization`'s grants of the catalogue's audit permissions, one set for each purpose (`read`, `count`,
  `export`, `verify`): `audit-log.{purpose}` for every category, `audit-log.{purpose}.{category}` for one of `security`,
  `access_management` and `audit`, and `audit-log.{purpose}.own` for the viewer's own activity. The scope is never
  wider than the grants allow and sees only the tenants the viewer belongs to, never the whole platform's trail (see
  [The audit trail](audit-trail.md#reading-the-trail)). Freshness for reading the trail belongs on the route that
  reads it: the policy is never told how the reader signed in, so a permission an authentication requirement guards,
  on its allow or on a deny, is not held there. Your own binding of the policy
  is kept, and a policy that replaces this package's decides who reads every person's trail, so a scope too wide
  (`AccessScope::all()`, or `withTenantless()` for a tenant's viewer) shows one tenant's viewer every tenant's people.
- **Its events in the audit trail.** `laravel-authorization`'s events are mapped to the `authorization.*` codes (see
  [The audit trail](audit-trail.md)), so audit-log's own Gate capture stays off.

## Its tables

`laravel-authorization`'s tables live on `authorization.connection` (`AUTHORIZATION_DB_CONNECTION`), which this package
aligns with the other members' keys: left unset, it is given `iam.storage.connection`, and naming another connection
refuses boot (`StorageConnectionMismatchException`, reported by `iam:check`). So a grant commits or rolls back with a
provisioned membership, SSO's scope widening runs in the grant's transaction, and the grant scope query reads your tree
on the same connection (see [Configuration](configuration.md#storage)).

## Pruning and checks

- `Iam::schedule()` registers `authorization:prune` daily, which removes expired grants and those of grantees and
  records that are gone (see [Operations](operations.md#the-schedule)). An expired grant stops counting at its expiry
  either way.
- `iam:check` runs `authorization:check`, which reports `laravel-authorization`'s settings, seams, grant hooks and
  connection, and fails the run when it refuses a setting (exit `1`) or could not complete its report (exit `3`) (see
  [Checks](checks.md#the-members-checks)). The worker reset forgets its request state between units of work (see
  [Operations](operations.md#workers-and-octane)).
- Each adapter in [What is bound](#what-is-bound) that this package binds over one of `laravel-authorization`'s
  contracts is declared to that report, so `authorization:check` names it rather than code whose class is decided at
  first use, as `[seam SubjectResolver] declared by laravel-iam; ...\SubjectResolverAdapter; scoped`. The tenant tree
  is declared as `one of ...\TenantTreeAdapter, ...\FlatTenantTree, decided at first resolution`, since which it builds
  depends on whether you name or bind a tree. The declaration names the very binding this package made, so once you
  bind over a contract the seam is shown as your binding, with `declared by laravel-iam as ..., but overridden later`,
  or `but an instance is bound over it` for an instance. A contract this package left to your binding, or whose switch
  is off, carries no declaration; one holding a class you name in `laravel-authorization`'s configuration reads
  `configured in` that key, with this package's declaration shown overridden where this package registered first.

## Further reading

- [The authorization design note](../design/authorization.md): how each seam is bound and answered.
- [Provisioning and tenancy](provisioning-and-tenancy.md#principal-scope): the principal scope's two halves.
- [The install and check design note](../design/install-and-check.md#what-the-authorization-glue-adds): what the checks gain.

[authorization-readme]: https://github.com/sinemacula/laravel-authorization/blob/master/README.md
[authentication-extending]: https://github.com/sinemacula/laravel-authentication/blob/master/docs/guides/extending.md
[mfa-middleware-answering]: https://github.com/sinemacula/laravel-mfa/blob/master/docs/guides/middleware.md#answering
