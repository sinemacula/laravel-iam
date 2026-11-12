# Provisioning and Tenancy

## Purpose

The package provisions a new identity for a `sign_in` SSO found unlinked, maps the provider's groups to grants, reports
a change that gives a person a principal to SSO's scope widening, and answers SSO's tenancy seams from the application's
memberships and `laravel-authorization`'s tenant tree. The grant hook is in `authorization.md`, the tenant
authentication policy in `tenant-authentication-policy.md`, and the storage connection and retries in
`storage-and-transactions.md`.

## Application contracts

The application binds these in the container; each is resolved on every call:

- `Contracts\Provisioner`: `createIdentity()` and `createMembership()`. With none bound, provisioning is off.
- `Contracts\Memberships`: `of(Identity): MembershipSet`, every current membership with the time the person accepted
  it, or the set marked incomplete.
- `Contracts\GroupMapping` and `Contracts\GroupResync`, both optional.
- `laravel-authorization`'s `TenantTree`, tested with that member's kit. It counts as a tree while it is not
  `FlatTenantTree`.

`FakeProvisioner`, `FakeMemberships` and `FakeGroupMapping` in `Testing` stand in for them in tests.

## SSO seams

`Tenancy\TenancySeams` binds these while `iam.adapters.sso` is on, each transient:

| SSO seam                 | Adapter                         | Default replaced          | Bound while          | Mandatory while           |
| ------------------------ | ------------------------------- | ------------------------- | -------------------- | ------------------------- |
| `TenantMembership`       | `TenantMembershipAdapter`       | `NoTenantMembership`      | memberships bound    | never                     |
| `LinkEligibility`        | `LinkEligibilityAdapter`        | `RefusingLinkEligibility` | memberships bound    | never                     |
| `PrincipalScope`         | `PrincipalScopeAdapter`         | `RefusingPrincipalScope`  | memberships bound    | never                     |
| `EnforcementInheritance` | `EnforcementInheritanceAdapter` | `OwnTenantInheritance`    | always               | enforcement on and a tree |

The membership rows are never mandatory because SSO's defaults fail closed. "Bound" means bound once every provider has
registered, so memberships bound in an application provider's `register()` count.

## Decisions

- `ProvisionOnUnlinkedResult` is the one listener of SSO's `ResultUnlinked`, registered whatever any switch says and
  doing nothing while no provisioner is bound. It runs synchronously, since SSO's event refuses to be serialised and its
  grant is void once the dispatch returns, and answers from the event alone.
- In one transaction on the storage connection, retried whole on a deadlock or serialisation failure, it writes in this
  order: the identity; the widening of its scope in the connection's tenant, so SSO's identity guard is taken first;
  the membership; SSO's `ProvisioningHelper::link()`; then the mapped groups' grants. Anything but `created` from the
  helper rolls every write back.
- The identity must be an Eloquent model with `wasRecentlyCreated` set, since SSO's grant proves the authority to
  provision, not that the identity is new.
- `ScopeWidenings::widen()` is the one call an application makes, first inside the transaction that gives people a
  principal in a tenant (or the platform, `null`). It runs SSO's `widened()` in a savepoint; outside a transaction SSO
  refuses it.
- `Memberships::of()` must take the application's membership guard as it answers, and every writer that narrows a
  membership must take it too, because SSO's `TenantMembership` asks for its answer to stay true until the redemption
  commits and offers no other protection. The adapters take no lock of their own.
- `TenantMembershipAdapter` and `LinkEligibilityAdapter` answer from the membership of exactly the tenant asked, and
  only an accepted one counts, since a `link` is the person's own act.
- `PrincipalScopeAdapter` is `outside_tenant` when the memberships or the grants are, `within_tenant` only when both
  are, and `unknown` otherwise. An incomplete membership set is `unknown`, never `outside_tenant`, since SSO latches a
  link suspended for good on `outside_tenant`.
- The grant half is `laravel-authorization`'s `GrantScopeQuery`, read through `GrantScopeAdapter`. With the
  authorization adapters off it is `UnknownGrantScope`, so nobody is `within_tenant`.
- `EnforcementInheritanceAdapter` answers the nearest tenant up the tree with a stored rule, on or off, or the tenant
  itself. A rule turned off therefore only loosens what applies below it, which matches SSO revoking nothing then. The
  reads take no lock, since locking the path would invert SSO's order against an admission.
- An enforcement change and a reported tree move judge the whole subtree through `SubtreePolicyChanges`, each tenant
  with `laravel-authentication`'s `tenantPolicyChanged()`. After the commit it lists the subtree again and judges any
  tenant it has gained, so a tenant moved in while the change was open is not missed. An enforcement change judges
  every descendant, which is broader than needed and never narrower.
- `TreeChanges::changed()` is called inside the move's transaction, after the write. With a tree it reports every
  identity granted within the moved tenant to SSO's widening (while the authorization and SSO adapters are both on),
  then calls `Authorization::treeChanged()`. It judges the subtree only while SSO's enforcement is on or MFA's tenant
  requirement is bound. A removal is reported as the move of each child, after the restructure is written.
- A `GrantInstruction` is a role and whether it reaches the tenants below, granted to the identity in the connection's
  tenant, so a connection's groups never grant beyond its tenant. `GroupSettings` finds the bound mapping, or
  `ConfiguredGroupMapping` while `iam.provisioning.groups.map` maps a group.
- The re-sync runs after the sign-in's transaction commits, in its own transaction, because its grants report to SSO's
  widening, whose identity guard comes before the locks the redemption holds. A refused re-sync hands out no
  credential. `MappedGroupResync` makes the identity's roles in the tenant exactly the mapping's, and refuses with no
  mapping rather than revoke every role.

## Invariants

- No write of a provisioning survives a refusal or a failure.
- A change that gives a person a principal or a grant reports it to SSO in its own transaction, so a rollback undoes
  the suspension too.
- Every tenant crosses to and from `laravel-authorization` through `TenantTranslator`, and one that does not resolve
  back throws `UnresolvedReferenceException`.
- No adapter reads the current request, user or guard, and none keeps anything between calls.

## Member gaps

- `laravel-authorization`'s `treeChanged()` runs no grant hook, so `TreeChanges` reports the grantees within a moved
  subtree to SSO itself.
- `laravel-sso`'s `RevocationScope::tenant()` names only the enforcing tenant, so `SubtreePolicyChanges` finds the
  inheriting tenants from the tree.
- `laravel-sso` locks only the enforcing tenant's rule, never the inheritance path, so the inheritance reads take no
  lock and may answer from a snapshot.
- `laravel-authentication` has no identity-creation contract, so the provisioner is the application's own.
