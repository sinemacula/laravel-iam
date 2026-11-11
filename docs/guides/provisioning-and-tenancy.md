# Provisioning and Tenancy

Who your people are, which tenants they belong to and how your tenants nest are your application's own data. The
members need answers from that data in several places, and must never disagree about a person or a tenant, so the
package asks you for each answer once, through a contract of its own, and routes it to every member that needs it.

| Contract                                                     | Configuration key                 | Answers                                                                                                                                                                   |
|--------------------------------------------------------------|-----------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `SineMacula\Laravel\Iam\Contracts\Provisioner`               | `iam.provisioning.provisioner`    | what a person signing in through SSO for the first time is made into                                                                                                      |
| `SineMacula\Laravel\Iam\Contracts\GroupMapping`              | `iam.provisioning.groups.mapping` | the roles a provider's groups give a person provisioned through it, in the connection's tenant (see [Group mapping](#group-mapping))                                      |
| `SineMacula\Laravel\Iam\Contracts\GroupResync`               | `iam.provisioning.groups.resync`  | whether, and how, a later sign-in brings a person's roles into line with the groups it reports                                                                            |
| `SineMacula\Laravel\Iam\Contracts\Memberships`               | `iam.tenancy.memberships`         | SSO's tenant membership, link eligibility and the membership half of principal scope                                                                                      |
| `SineMacula\Laravel\Mfa\Contracts\TenantRequirement`         | None: bind it                     | MFA's tenant requirement and the tenant's part of the tenant policy (see [The tenant MFA requirement](#the-tenant-mfa-requirement))                                       |
| `SineMacula\Laravel\Authentication\Contracts\TenantResolver` | None: bind it                     | every tenant id to its tenant, owed with MFA's tenant requirement, SSO's enforcement, or `laravel-authorization`'s glue (see [The tenant resolver](#the-tenant-resolver)) |

Name each by its class in `config/iam.php`, or bind it in the container in a service provider's `register()`.
Memberships bound only from a `boot()` are still the ones asked, but bind no adapter, so SSO's own defaults stay. The
tenant tree is `laravel-authorization`'s (see [The tenant tree](#the-tenant-tree)). A value that is no class name fails
closed. Each is optional: leave it unnamed and the member's own default, which refuses or requires nothing, stays.

Every one of them is asked inside the members' transactions on the storage connection, some under SSO's locks, so:

- read the write connection every time (`SineMacula\Laravel\Authentication\Database\WriteConnection`), cache nothing,
  and keep nothing of one call for the next;
- write only on the storage connection: a write elsewhere is not atomic with the members' and survives a rollback;
- refuse by throwing. A read that fails throws; it never answers "nothing" because it could not tell.

The testing fakes and contract kits for this package's own contracts are in [Testing](testing.md).

## The tenant resolver

`laravel-authentication`'s `SineMacula\Laravel\Authentication\Contracts\TenantResolver` is not this package's contract,
but the package depends on it: granting anything in a tenant through `laravel-authorization` while the authorization
and SSO adapters are on (`iam.adapters.authorization` and `iam.adapters.sso`, both on by default), binding MFA's tenant
requirement, or turning SSO's enforcement on (with or without a tenant tree), requires binding a resolver that resolves
every tenant id to the tenant whose `getTenantIdentifier()` is exactly that id. The tenant policy,
`Iam::treeChanges()->changed()` and SSO's revocation all resolve a session's
tenant id through it, and the [grant hook](authorization.md#grants-the-tree-and-sso) the tenant of every grant that
widens an identity's scope: a grant to the identity always widens, and so does a principal's first grant in a tenant,
so an ordinary role assignment in a tenant needs it even with linking by a verified domain off. This applies even when
your principals only ever act in their own tenant: `laravel-authentication` admits a principal's own tenant without
asking a resolver, so an application that never needed one before needs one now. Under `laravel-authentication`'s
default, `SineMacula\Laravel\Authentication\Tenancy\ResolveNoTenant`, each of them throws
`SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException`, so every such grant, tree move or revocation answers a
server error. Bind yours in a service provider's `register()`; `iam:check` refuses
`ResolveNoTenant` while the authorization and SSO adapters are both on, MFA's tenant requirement is bound or SSO's
enforcement is on (see [Checks](checks.md#configuration)), and `laravel-authentication`'s
[extending guide][auth-extending] describes the contract.

While `iam.adapters.authorization` is on, the resolver names your tenants to `laravel-authorization` too: the grant
hook, the grant half of the [principal scope](#principal-scope), `AdministrativeCheck` for an object in a tenant (see
[Authorization](authorization.md#administrative-operations-and-the-trail)), the roles your
[group mapping](#group-mapping) grants and every [tree change](#the-tenant-tree) you report resolve the tenant id
through it, and hand `laravel-authorization` the tenant it answers. That tenant must be an Eloquent model or
`laravel-authorization`'s `AuthorizableTenant`, and its key must be its `getTenantIdentifier()`, byte for byte, since
`laravel-authentication` records a session's tenant by the one and `laravel-authorization` keys a grant by the other;
any other answer throws `UnresolvedReferenceException`, and the change being made rolls back. The
[audit trail](audit-trail.md#authorization-decisions) names the tenant of each `authorization.*` record the same way,
and records one that does not resolve back with no tenant.

## Provisioning

With a provisioner named, a person signing in through an SSO connection for the first time is made into a new identity
and a membership of the connection's tenant, just in time, inside the flow:

```php
// config/iam.php
'provisioning' => [
    'provisioner' => App\Identity\ProvisionPeople::class,
],
```

```php
use App\Models\Member;
use App\Models\User;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Iam\Contracts\Provisioner;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

final class ProvisionPeople implements Provisioner
{
    public function createIdentity(#[\SensitiveParameter] VerifiedResult $result): Identity
    {
        // Always a new identity, inserted now: never one found by an attribute
        return User::create(['name' => $result->attributes['display_name'] ?? 'New person']);
    }

    public function createMembership(Identity $identity, string $tenantId, #[\SensitiveParameter] VerifiedResult $result): void
    {
        Member::create(['user_id' => $identity->getAuthIdentifier(), 'tenant_id' => $tenantId]);
    }
}
```

The package's one listener of SSO's `ResultUnlinked` asks it, only for a `sign_in` that resolved to no identity and
holds no reservation. In one transaction on the storage connection, attempted once, it creates the identity, reports
the new principal through SSO's scope widening, creates the membership, and links the result to the identity through
SSO's provisioning helper. Anything thrown, or a refusal from the helper, rolls all of it back; once it commits, the
identity, its membership and its link stay made, and the person's next sign-in resolves through the link.

- **Always a new identity.** Never look one up by the result's email address, subject or any other attribute: whoever
  controls the connection's attributes could take over an existing account. An existing person joins a connection
  through SSO's `link` purpose or a verified domain instead.
- **Answer the Eloquent model you just inserted.** One whose `wasRecentlyCreated` is false is refused with a
  `LogicException` and rolled back.
- **Take no lock on rows other writers share** (a tenant-wide row, say): SSO takes its own locks next, and a shared lock
  taken before them inverts its order. Guarding the new identity's own rows is safe.
- **Register no provisioning listener of your own beside it.** Every listener shares SSO's one grant.
- **Whether the membership counts as accepted** by the person is yours to record (see [Memberships](#memberships)).
- **Groups and custom attributes.** `$result->attributes` holds what the connection's mapping carries: SSO's standard
  targets, `groups` among them, and the custom keys you declare in `sso.mapping.custom_attributes`. Leave the groups to
  the [group mapping](#group-mapping), which grants their roles once the link is made; your provisioner writes no grant
  of its own from them.

With no provisioner, a `sign_in` that resolves to no identity ends as SSO's `unlinked`. SSO's side of this is in its
[provisioning guide][sso-provisioning].

## Group mapping

SSO reports the groups a connection maps (its `groups` attribute) on every verified result, and changes nothing with
them. Map them to `laravel-authorization`'s roles, and the person a first sign-in provisions holds those roles from the
start:

```php
// config/iam.php
'provisioning' => [
    'provisioner' => App\Identity\ProvisionPeople::class,
    'groups'      => [
        'map' => [
            'finance'     => 'invoices.viewer',
            'finance-ops' => ['invoices.viewer', 'invoices.approver'],
        ],
    ],
],
```

Each role is granted to the new identity itself, which holds across every principal of it, in the tenant of the
connection the groups came through, reaching that tenant alone, in every application and never expiring. The grants
are made through `laravel-authorization`'s grant service, as trusted system work, in the provisioning's one
transaction, once SSO's helper has made the link: a role that does not exist, a mapping that throws, or a grant hook
that refuses rolls the identity, its membership and its link back with it, and the completion ends as a server error.
Groups are compared byte for byte, a group the map does not name grants nothing, and a connection that reports no
groups grants nothing.

A mapping that tells one connection's groups from another's, or grants a role across the tenant's subtree, is a class of
yours, named in `iam.provisioning.groups.mapping` or bound in the container (which wins over the map):

```php
use SineMacula\Laravel\Iam\Contracts\GroupMapping;
use SineMacula\Laravel\Iam\Provisioning\GrantInstruction;

final readonly class ConnectionGroups implements GroupMapping
{
    public function grantsFor(string $connectionId, string $tenantId, array $groups): array
    {
        return in_array('admins', $groups, true) ? [GrantInstruction::roleWithSubtree('tenant.admin')] : [];
    }
}
```

Answer from the values given alone, the same for the same values, and write nothing: it is asked after SSO's locks.
A `GrantInstruction` names a role and whether it reaches the tenants below the connection's, never a tenant of its own:
a connection's groups never grant beyond its tenant and its subtree, and never platform-wide. Provider groups are only
as trustworthy as the connection, whose tenant's administrator may control what it reports.

### Re-syncing at later sign-ins

What provisioning granted stays until you change it: SSO's later sign-ins report the groups again but change nothing.
To bring a person's roles into line with their groups at every sign-in, opt in:

```php
'groups' => [
    'map'    => [/* ... */],
    'resync' => SineMacula\Laravel\Iam\Provisioning\MappedGroupResync::class,
],
```

`Iam::signIns()->redeem()` then calls it for every `sign_in` that links an identity and signs it in, once the
redemption's transaction has committed, in a transaction of its own, and before the credential is handed back to you.
`MappedGroupResync` makes the identity's own roles in the connection's
tenant exactly those the mapping now answers: a group added grants its roles, a group removed revokes them, and a role
the mapping does not answer is never granted. It also revokes a role an administrator granted the identity itself in
that tenant, so grant those to the person's principal instead, or implement `Contracts\GroupResync` yourself (named in
`iam.provisioning.groups.resync`, or bound); roles of the identity's principals, of another tenant, or platform-wide
are never touched. A grant that widens the person's scope reports it to SSO first, which takes SSO's identity guard
before any of SSO's other locks, so the re-sync never runs under the redemption's locks, which would deadlock with a
grant or a link of the same person made meanwhile. A re-sync that throws grants and revokes nothing, and reaches you
from `redeem()` once the sign-in has committed: the code is spent, and the session written is never handed out, so
nobody can use it; the person signs in again. Grants are read on every check, so nothing in the session depends on the
re-sync. Call `redeem()` with no transaction of your own open on the storage connection: inside one, the re-sync runs
under the redemption's locks after all.

## Scope widening

Any other change that gives a person a principal (a membership created or accepted, a platform principal created)
reports it to SSO first, inside its own transaction on the storage connection, before the principal is written:

```php
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Iam\Facades\Iam;

Iam::transaction(function () use ($identity, $tenantId, $request): void {
    Iam::scopeWidenings()->widen([$identity], $tenantId, ClientContext::fromRequest($request));

    // ...take your own guard of the person's principals, then write the membership
});
```

Pass `null` as the tenant for a platform principal, and `new ClientContext(null, null)` from a console command or a job.
A change that gives several people a principal in the same tenant passes them together, so SSO takes their guards in its
order. SSO suspends the person's links by a verified domain in every other tenant's connection, and revokes the sessions
established through each, in the same transaction. Called with no transaction open it is SSO's `LogicException`, with
nothing written. See SSO's [linking by domain guide][sso-linking-by-domain].

## Memberships

```php
use App\Models\Member;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Iam\Contracts\Memberships;
use SineMacula\Laravel\Iam\Tenancy\Membership;
use SineMacula\Laravel\Iam\Tenancy\MembershipSet;

final readonly class TenantMemberships implements Memberships
{
    public function of(Identity $identity): MembershipSet
    {
        $members = WriteConnection::query(Member::query())
            ->where('user_id', $identity->getAuthIdentifier())
            ->whereNull('revoked_at')
            ->sharedLock()
            ->get();

        return MembershipSet::complete(...$members->map(static fn (Member $member): Membership => $member->tenant_id === null
            ? Membership::platform($member->accepted_at?->toImmutable())
            : Membership::of((string) $member->tenant_id, $member->accepted_at?->toImmutable())));
    }
}
```

Answer every current membership, a platform principal among them, each with the time the person accepted it (a
`CarbonImmutable`): never the time an administrator created or imported it, and none for an invitation not taken up.
`Membership::of()` and `Membership::platform()` take only a `CarbonImmutable`, and an attribute cast as `datetime`, as
Laravel casts a timestamp by default, is a mutable `Illuminate\Support\Carbon` that neither accepts, so the example
converts it with `toImmutable()`. A model that casts `accepted_at` as `immutable_datetime` may pass it as it is.
A set you cannot read completely is answered with `MembershipSet::incomplete()`, never as though it were complete. A
revoked or expired membership is no current one.

It is asked at a completion and again inside a redemption's transaction, under SSO's locks, and SSO relies on the
answer staying true until that transaction commits. So take your membership guard of the identity as you read: a lock
held until the asking transaction ends, such as the shared lock above. Every writer that revokes, expires or narrows a
membership takes the same guard before it writes and before it ends the person's sessions.

With memberships named, SSO's tenant membership, link eligibility (a `link` only by an accepted membership of the
connection's tenant) and the membership half of its principal scope are answered from them. Without them SSO's defaults
stay: no membership, no `link`, and no linking by a domain.

## Principal scope

SSO's principal scope says whether everything a person holds stays within one tenant, which linking by a verified domain
requires. Its membership half is answered from your memberships, and its grant half from `laravel-authorization`'s grant
scope query: `within_tenant` only when both are, and `outside_tenant` when either is, which suspends a verified domain
link for good. The query counts the live grants of the identity and of every principal it owns, as its `principals()`
relation lists them, your principal model's global scopes set aside, so a soft-deleted principal still counts until its
grants are revoked. An identity that is itself a principal and owns none acts as itself alone. An identity that is
neither a principal nor owns principals (`HasPrincipals`), whose principals only a principal resolver you bind to
`laravel-authentication` knows, leaves the grant half `unknown`, as does a `principals()` that is no Eloquent relation
or query: give such an identity a `principals()` relation to have it linked by a verified domain. The query places a
grant in the tenant or below it in your [tree](#the-tenant-tree) within it, and one anywhere else (another tenant, an
ancestor, the platform) outside it. Keep the tree's subtree query on the storage connection: the query nests it there,
and a tree it cannot read answers `unknown`. It names the tenant through your [tenant resolver](#the-tenant-resolver).

With `iam.adapters.authorization` off, the grant half is `Iam\Tenancy\UnknownGrantScope`, which answers `unknown`, so
the principal scope is never `within_tenant` and SSO links nobody by a verified domain, unless you bind a grant half
of your own (`Iam\Tenancy\Contracts\GrantScope`).

A grant that takes a person beyond a tenant reports it to SSO first, in the grant's own transaction, through
`laravel-authorization`'s grant hook (see [Authorization](authorization.md)): SSO suspends the person's links by every
other tenant's verified domain and revokes the sessions established through them, as a membership's
[scope widening](#scope-widening) does. A grant made inside your own transaction rolls the suspension back with it.

## The tenant tree

Implement `laravel-authorization`'s `SineMacula\Laravel\Authorization\Contracts\TenantTree` and name it in
`authorization.tenant_tree`; its `SineMacula\Laravel\Authorization\Testing\Concerns\TenantTreeContract` tests your
implementation. Tenants of different types may nest. This package reads the same tree: a tenant inherits SSO's
enforcement from the nearest tenant, from itself up, with a rule stored, on or off, and an enforcement change judges the
sessions of the enforcing tenant and every tenant below it. With `laravel-authorization`'s flat default every tenant
stands alone.

Report every move of a tenant inside the transaction that writes it, after the write, and a removal as the move of
each child moved out from under the removed tenant:

```php
use SineMacula\Laravel\Iam\Facades\Iam;

Iam::transaction(function () use ($organisation, $parentId): void {
    $organisation->update(['parent_id' => $parentId]);

    Iam::treeChanges()->changed((string) $organisation->getKey());
});
```

The report passes the move to `laravel-authorization` (`Authorization::treeChanged()`: do not call it yourself beside
it). While the authorization and SSO adapters are on, it reports everyone granted in the moved subtree to SSO's
[scope widening](#scope-widening), since no grant hook runs for a move. While SSO's enforcement is on or MFA's tenant
requirement is bound, it judges the sessions of the moved subtree, once in the transaction and once more after it
commits. It resolves each tenant through your [tenant resolver](#the-tenant-resolver).

## The tenant MFA requirement

Which tenants require which further factors is yours to answer: implement laravel-mfa's `TenantRequirement` and bind
it in a service provider's `register()`.

```php
use App\Models\Organisation;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\TenantRequirement;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

final readonly class OrganisationRequirements implements TenantRequirement
{
    public function requirementFor(MultiFactorAuthenticatable $identity, string $application, string $tenant): Requirement
    {
        return Organisation::query()->findOrFail($tenant)->requires_mfa
            ? Requirement::none()->withMultifactor(43200)
            : Requirement::none();
    }
}

$this->app->bind(TenantRequirement::class, OrganisationRequirements::class);
```

MFA asks it itself. While `iam.adapters.sso` is on, the package also reads it into `laravel-authentication`'s tenant
authentication policy, inside `WriteConnection::during()` for the tenant, so the two members never disagree about a
tenant. The policy's version is a digest of the answer, so it changes whenever the answer does. Once you bind one, an
identity that is not `MultiFactorAuthenticatable` acting in a tenant is refused with `UnresolvedReferenceException`.
It applies no inheritance down the tree, and it is asked under the session's row lock at times: take no lock and write
nothing. Test it with laravel-mfa's `TenantRequirementTests` kit.

When the answer changes, report it inside the transaction that publishes it:

```php
use SineMacula\Laravel\Iam\Facades\Iam;

Iam::transaction(function () use ($organisation, $tenant): void {
    $organisation->update(['requires_mfa' => true]);

    Iam::tenantPolicies()->changed($tenant);
});
```

It judges the tenant's sessions there, so both commit or roll back together, and once more after the transaction
commits, so a session that entered the tenant meanwhile, having read the old answer, is judged too. Bearer requests
never recheck a tenant's policy, so without the report a session that no longer meets it acts on its access tokens
until they expire. Calling `Auth::sessions()->tenantPolicyChanged($tenant)` yourself, call it twice the same way: once
inside the transaction and once after it commits.

A bound requirement needs your [tenant resolver](#the-tenant-resolver): the tenant policy resolves the session's tenant
through it.

With MFA's default left bound, no tenant requires a further factor; SSO's enforcement still applies. How the answer meets
SSO's enforcement is in [Authentication and SSO](authentication-and-sso.md#the-tenant-policy).

The same report, `Iam::tenantPolicies()->changed($tenant)`, is owed whenever your `EnforcementExemption` grants or
withdraws an identity's exemption, for every tenant concerned, inside the transaction that writes it, as [Authentication
and SSO](authentication-and-sso.md#the-tenant-policy) shows.

## Further reading

- [The provisioning and tenancy design note](../design/provisioning-and-tenancy.md).
- [The tenant authentication policy design note](../design/tenant-authentication-policy.md).

[sso-provisioning]: https://github.com/sinemacula/laravel-sso/blob/master/docs/guides/provisioning.md
[sso-linking-by-domain]: https://github.com/sinemacula/laravel-sso/blob/master/docs/guides/linking-by-domain.md
[auth-extending]: https://github.com/sinemacula/laravel-authentication/blob/master/docs/guides/extending.md
