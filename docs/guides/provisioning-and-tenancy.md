# Provisioning and Tenancy

Who your people are, which tenants they belong to and how your tenants nest are your application's own data. The
members need answers from that data in several places, and must never disagree about a person or a tenant, so the
package asks you for each answer once, through a contract of its own, and routes it to every member that needs it.

| Contract                                                     | Configuration key              | Answers                                                                                                                                  |
|--------------------------------------------------------------|--------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|
| `SineMacula\Laravel\Iam\Contracts\Provisioner`               | `iam.provisioning.provisioner` | what a person signing in through SSO for the first time is made into                                                                     |
| `SineMacula\Laravel\Iam\Contracts\Memberships`               | `iam.tenancy.memberships`      | SSO's tenant membership, link eligibility and the membership half of principal scope                                                     |
| `SineMacula\Laravel\Iam\Contracts\TenantTree`                | `iam.tenancy.tree`             | SSO's enforcement inheritance, and which sessions a change reaches                                                                       |
| `SineMacula\Laravel\Iam\Contracts\TenantMfaRequirement`      | `iam.tenancy.mfa_requirement`  | MFA's tenant requirement and the tenant's part of the tenant policy                                                                      |
| `SineMacula\Laravel\Authentication\Contracts\TenantResolver` | None: bind it                  | every tenant id to its tenant, owed with a tenant MFA requirement or SSO's enforcement (see [The tenant resolver](#the-tenant-resolver)) |

Name each by its class in `config/iam.php`, or bind it in the container in a service provider's `register()`.
Memberships or a tree bound only from a `boot()` are still the ones asked, but bind no adapter, so SSO's own defaults
stay. A value that is no class name fails closed. Each is optional: leave it unnamed and the member's own
default, which refuses or requires nothing, stays.

Every one of them is asked inside the members' transactions on the storage connection, some under SSO's locks, so:

- read the write connection every time (`SineMacula\Laravel\Authentication\Database\WriteConnection`), cache nothing,
  and keep nothing of one call for the next;
- write only on the storage connection: a write elsewhere is not atomic with the members' and survives a rollback;
- refuse by throwing. A read that fails throws; it never answers "nothing" because it could not tell.

The testing fakes and contract kits for this package's four are in [Testing](testing.md).

## The tenant resolver

`laravel-authentication`'s `SineMacula\Laravel\Authentication\Contracts\TenantResolver` is not this package's contract,
but the package depends on it: naming a tenant MFA requirement, or turning SSO's enforcement on (with or without a
tenant tree), requires binding a resolver that resolves every tenant id to the tenant whose `getTenantIdentifier()` is
exactly that id. MFA's tenant requirement (`Iam\Mfa\TenantRequirementAdapter`), `Iam::treeChanges()->changed()` and
SSO's revocation all resolve a session's tenant id through it. This applies even when your principals only ever act in
their own tenant: `laravel-authentication` admits a principal's own tenant without asking a resolver, so an application
that never needed one before needs one now. Under `laravel-authentication`'s default,
`SineMacula\Laravel\Authentication\Tenancy\ResolveNoTenant`, each of them throws
`SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException`, so every MFA-gated request from a session in a tenant
answers a server error. Bind yours in a service provider's `register()`; `iam:check` refuses `ResolveNoTenant` while a
tenant MFA requirement is named or SSO's enforcement is on (see [Checks](checks.md#configuration)), and
`laravel-authentication`'s [extending guide][auth-extending] describes the contract.

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
- **Insert it in the call, with its model events on.** The listener witnesses the `created` event of the model the call
  inserts, so an instance inserted before the call, a fresh copy of the row, or one inserted quietly
  (`createQuietly()`, `saveQuietly()`, `withoutEvents()`) is refused with a `LogicException` and rolled back.
- **Take no lock on rows other writers share** (a tenant-wide row, say): SSO takes its own locks next, and a shared lock
  taken before them inverts its order. Guarding the new identity's own rows is safe.
- **Register no provisioning listener of your own beside it.** Every listener shares SSO's one grant.
- **Whether the membership counts as accepted** by the person is yours to record (see [Memberships](#memberships)).
- **Groups and custom attributes.** `$result->attributes` holds what the connection's mapping carries: SSO's standard
  targets, `groups` among them, and the custom keys you declare in `sso.mapping.custom_attributes`. Mapping a
  provider's groups to grants waits for `laravel-authorization`'s glue (see [Authorization](authorization.md)); until
  then your provisioner writes any grant itself.

With no provisioner, a `sign_in` that resolves to no identity ends as SSO's `unlinked`. SSO's side of this is in its
[provisioning guide][sso-provisioning].

## Scope widening

Any other change that gives a person a principal (a membership created or accepted, a platform principal created)
reports it to SSO first, inside its own transaction on the storage connection, before the principal is written:

```php
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Iam\Facades\Iam;

Iam::transaction(function () use ($identity, $tenantId, $request): void {
    Iam::scopeWidenings()->widen($identity, $tenantId, ClientContext::fromRequest($request));

    // ...take your own guard of the person's principals, then write the membership
});
```

Pass `null` as the tenant for a platform principal, and `new ClientContext(null, null)` from a console command or a
job. SSO suspends the person's links by a verified domain in every other tenant's connection, and revokes the sessions
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

SSO's principal scope says whether everything a person holds stays within one tenant, which linking by a verified
domain requires. Its membership half is answered from your memberships; its grant half needs `laravel-authorization`'s
grant scope query, which is not bound yet (see [Authorization](authorization.md)). Until it is, the principal scope is
never `within_tenant`, so SSO links nobody by a verified domain, and a complete set of memberships reaching beyond the
tenant is `outside_tenant`, which suspends a verified domain link for good.

## The tenant tree

```php
// config/iam.php
'tenancy' => [
    'tree' => App\Tenancy\Organisations::class, // implements SineMacula\Laravel\Iam\Contracts\TenantTree
],
```

The tree names tenants by the opaque identifiers SSO and `laravel-authentication` use, has no cycles, and answers:

- `ancestors($tenantId)`: nearest first, the tenant excluded; nothing for a root or a tenant it does not hold;
- `descendants($tenantId)`: every tenant below, each once, the tenant excluded;
- `isWithin($tenantId, $ancestorId)`: agreeing with both, a tenant counting as within itself;
- `subtree($tenantId)`: a query of the tenant and every descendant, selecting their ids in the `tenant_id` column
  (`TenantTree::ID_COLUMN`).

With a tree named, a tenant inherits SSO's enforcement from the nearest tenant, from itself up through its ancestors,
that has a rule stored, on or off: a rule turned off keeps its tenant, and every tenant inheriting from it, out of an
ancestor's rule. An enforcement change judges the sessions of the enforcing tenant and of every tenant below it.
Without a tree every tenant stands alone.

Report every move of a tenant inside the transaction that writes it, after the write, and a removal as the move of
each child moved out from under the removed tenant:

```php
use SineMacula\Laravel\Iam\Facades\Iam;

Iam::transaction(function () use ($organisation, $parentId): void {
    $organisation->update(['parent_id' => $parentId]);

    Iam::treeChanges()->changed((string) $organisation->getKey());
});
```

While SSO's enforcement is on or a tenant MFA requirement is named, it judges the sessions of the moved tenant and its
whole subtree, once in the transaction and once more after it commits; otherwise nothing can have changed, and it
reads nothing. A report made before the write would judge the tree as it was. It resolves each tenant through your
[tenant resolver](#the-tenant-resolver), and throws `UnresolvedReferenceException` under `ResolveNoTenant`.

## The tenant MFA requirement

Which tenants require which further factors is yours to answer, once, for exactly the tenant asked:

```php
use App\Models\Organisation;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Iam\Contracts\TenantMfaRequirement;
use SineMacula\Laravel\Iam\Tenancy\TenantMfaRule;

final readonly class OrganisationRequirements implements TenantMfaRequirement
{
    public function requirementFor(Tenant $tenant, string $application): TenantMfaRule
    {
        $organisation = WriteConnection::query(Organisation::query())->findOrFail($tenant->getTenantIdentifier());
        $version      = 'mfa-' . $organisation->mfa_revision;

        return $organisation->requires_mfa
            ? new TenantMfaRule(new Requirement(multifactor: new RequirementPart(maxAgeSeconds: 43200)), $version)
            : TenantMfaRule::none($version);
    }
}
```

The package hands the one answer to MFA's tenant requirement and to `laravel-authentication`'s tenant authentication
policy, so the two never disagree about a tenant. It applies no inheritance down the tree: a tenant that inherits a
requirement is worked out here. It is asked at sign-in, at a choice of principal, at activation, on every refresh and
switch, and while MFA works out a session's requirement, sometimes under the session's row lock: take no lock and
write nothing.

The rule's version must change whenever the answer does, and stay the same while it does not, so a session recorded at
the version is not judged again for nothing; a `null` version is never taken as already checked. When the answer
changes, report it inside the transaction that publishes it:

```php
use SineMacula\Laravel\Iam\Facades\Iam;

Iam::transaction(function () use ($organisation, $tenant): void {
    $organisation->update(['requires_mfa' => true, 'mfa_revision' => $organisation->mfa_revision + 1]);

    Iam::tenantPolicies()->changed($tenant);
});
```

It judges the tenant's sessions there, so both commit or roll back together, and once more after the transaction
commits, so a session that entered the tenant meanwhile, having read the old answer, is judged too. Bearer requests
never recheck a tenant's policy, so without the report a session that no longer meets it acts on its access tokens
until they expire. Calling `Auth::sessions()->tenantPolicyChanged($tenant)` yourself, call it twice the same way: once
inside the transaction and once after it commits.

A tenant MFA requirement needs your [tenant resolver](#the-tenant-resolver): MFA's requirement resolves the session's
tenant through it, and under `laravel-authentication`'s default `ResolveNoTenant` every MFA-gated request from a
session in a tenant throws `UnresolvedReferenceException`, even when the session acts in its principal's own tenant.

With no requirement named, no tenant requires a further factor; SSO's enforcement still applies. How the answer meets
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
