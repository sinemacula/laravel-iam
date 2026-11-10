# Provisioning and Tenancy

## Purpose

This note describes how the package provisions a new identity for a `sign_in` SSO found unlinked (IAM-7.1), how it
maps the provider's groups to grants at provisioning and, where the application opts in, at later sign-ins (IAM-7.2),
how a change that gives a person a principal or a grant reports it to SSO first (IAM-7.3, IAM-6.7), and how the
application's memberships and tenant tree answer SSO's link judgements and enforcement inheritance and
`laravel-authorization`'s tree, with `laravel-authorization`'s grant scope query as the grant half of the principal
scope (IAM-7.4, IAM-7.5, IAM-6.8). It covers the
application's contracts, the one listener of SSO's `ResultUnlinked` and the order of its writes inside its one
transaction, the scope widening service and the transaction it must run in, the configuration that turns each on, the
testing kits and fakes the package ships for the application's contracts, and the gaps in the members the adapters
work around. The redemptions and SSO's revocation scopes are in `sso-redemption-and-revocation.md`, the tenant
authentication policy in `tenant-authentication-policy.md`, the binding rule in `binding-precedence.md`, and the
storage connection and the retry helper in `storage-and-transactions.md`.

## Invariants

- What a provisioned identity and its membership are is the application's own. The application implements
  `Contracts\Provisioner` once: `createIdentity(VerifiedResult $result): Identity` and
  `createMembership(Identity $identity, string $tenantId, VerifiedResult $result): void`, names it in
  `iam.provisioning.provisioner` or binds it in the container (which wins, IAM-8.4), and
  `Provisioning\ProvisioningSettings` resolves it from the container at each dispatch, so one bound after this package
  registers, from a provider's `boot()` or once the application has booted, counts too. With none named or bound
  (`null`, or blank text), provisioning is off and an unlinked `sign_in` ends as SSO's `unlinked`. A class named that is
  no provisioner, a value that is no class name at all (`true`, `false`, a number, an array), or a binding that resolves
  to no provisioner, throws `ProvisionerMisconfiguredException` at the dispatch, before anything is written, never
  turning provisioning off. `createMembership()` answers nothing: the group mapping grants to the new identity itself,
  which holds across every principal of it, so nothing reads a principal from it.
- `Provisioning\ProvisionOnUnlinkedResult` is the package's one listener of SSO's `Events\ResultUnlinked`, registered
  in `boot()` whatever any switch says (`ProvisionOnUnlinkedResult::listen()`, called from
  `IamServiceProvider::boot()`), and doing nothing at all, no read and no transaction, while no provisioner is
  configured. It listens to SSO's event alone, never to `laravel-authentication`'s informational
  `ExternalResultUnlinked`, which would provision twice (AUTH-3.9). It runs
  synchronously, never queued: SSO's event refuses to be serialised, and its grant is void once the dispatch returns.
  The listener and its collaborators are resolved from the application current at the dispatch, never from the events
  dispatcher's container, so under Octane they are the request's sandbox's.
- It answers only from the event: the result is `$event->result`, the grant `$event->grant`, and the client the
  event's context's IP address and user agent, the completion's own. It reads no request, nor the current user.
- In one transaction on the storage connection (`CrossMemberTransaction`), in this order:
  1. `Provisioner::createIdentity($result)`, which must answer the very Eloquent model instance this call inserted:
     the listener asks it with every model's `created` event witnessed (`Provisioning\InsertionWitness`, which stands in
     for Eloquent's dispatcher only while the call runs and passes everything on), and anything else, an identity found
     by an attribute, one inserted before the call and kept (whose `wasRecentlyCreated` stays set), a fresh instance of
     the row, or one inserted with its model events off, is a `LogicException` and rolls back. The grant proves the
     authority to provision for the result, not that the identity is new, so the check is the package's, and the kit
     proves the rest;
  2. `Tenancy\ScopeWidenings::widen()` for the new identity and the connection's tenant, first among the writes that
     give a person a principal: SSO takes the new identity's guard, the first of its locks, and finds nothing to
     suspend;
  3. `Provisioner::createMembership($identity, $result->tenantId, $result)`;
  4. SSO's `ProvisioningHelper::link($event->grant, $event->result, $reference, $client)`, with the identity named by
     its morph class and key (`IdentityReferences::reference()`), which takes the enforcing tenant's rule, the
     connection, the request and the links, in SSO's lock order, as a savepoint.
- The transaction commits only when the helper answers `created`. It is attempted once, never retried: the helper
  claims the grant in memory before anything else, and a rollback does not unclaim it, so a second attempt could only be
  refused `grant_invalid`. It is committed or rolled back before the listener returns, as SSO requires.
- On PostgreSQL, MySQL and MariaDB the one attempt reads committed rows, whatever level the storage connection runs at
  (`Provisioning\CommittedReads`). The listener cannot retry, since the grant is spent, so no first sign-in running
  beside it may fail it:
  - On PostgreSQL, every link SSO makes raises its connection's `links_version`, so at REPEATABLE READ any link
    committed in the connection while the listener runs, another person's first sign-in included, would fail the
    helper's locking read of the connection to serialise (`40001`).
  - On MySQL and MariaDB, at InnoDB's REPEATABLE READ, the widening's locking read of the new identity's links
    (`rowsOf($identity)->lockForUpdate()`) finds none and gap-locks the links' identity index; the helper then takes
    the enforcing tenant's rule and the connection and inserts the link into that index, so the listener would hold
    the links (lock 6) before the rule and the connection (locks 2 and 3), out of SSO's order. Gap locks never conflict
    with each other, but each blocks the other transaction's insert: two first sign-ins whose identities fall in the
    same gap, or a first sign-in and a `link` redemption or a reservation for an existing identity there (any
    connection, since the gap is the identity index's), deadlock (`1213`), and the victim's completion ends as a
    server error. Locking reads read the latest committed rows at either level, but only READ COMMITTED takes no gap
    lock for them.

  At READ COMMITTED the locking reads wait for the other transaction's commit and see it, InnoDB takes no gap locks
  for them, and the helper re-reads the connection, the request and the links under its own locks, so nothing is
  lost. The engines take the level at different moments: MySQL and MariaDB refuse to change it inside an open
  transaction and apply `set transaction isolation level read committed` to the next one the session begins, so it is
  issued before `CrossMemberTransaction::run()` begins the listener's transaction, with none open
  (`beforeBeginning()`); PostgreSQL takes it only inside a transaction, before its first statement, so it is the
  listener's first statement there (`onceBegun()`). SQLite's level is kept, and so is the level of a caller's
  transaction the listener runs inside, in a savepoint, already past its first statement. On MySQL, READ COMMITTED
  needs row-based binary logging where the binary log is on, as MySQL 8's default `binlog_format` gives; MariaDB's
  default mixed format switches to rows for it.
- The membership is written between SSO's first lock and the rest, so a provisioner takes no lock on rows other writers
  share before the helper runs: SSO's order puts the application's guards after the rule, the connections and the
  links. A guard of the new identity's own rows is safe, since no other transaction can name the identity before this
  one commits. Inserting a new row needs no guard.
- `Tenancy\ScopeWidenings::widen(Identity $identity, ?string $tenantId, ClientContext $client): int` is the one core
  method an application calls, as `Iam::scopeWidenings()->widen(...)`, first inside the transaction on the storage
  connection that gives a person a principal: a membership created or accepted, or a platform principal (`null`
  tenant). It names the identity to SSO by its morph class and key, translates `laravel-authentication`'s client to
  SSO's (`ClientTranslator::toSso()`), resolves SSO's `Linking\ScopeWidening` on each call and answers how many links it
  suspended. Inside the caller's transaction it runs once, in a savepoint of it (`CrossMemberTransaction`); outside one
  it is SSO's `LogicException`. It reads no request, nor the current user, and keeps nothing (IAM-8.1).

- What a membership and the tenant tree are is the application's own. It implements `Contracts\Memberships`
  (`of(Identity): MembershipSet`, every current membership, a platform principal among them, each with the time the
  person, never an administrator, accepted it, or the set marked incomplete) and `Contracts\TenantTree` (`ancestors()`
  nearest first, `descendants()`, `isWithin()`, `subtree()` as a query selecting `tenant_id`), and names each in
  `iam.tenancy.memberships` and `iam.tenancy.tree`, or binds it in the container, which wins (IAM-8.4). Both are
  resolved on every call (`Tenancy\TenancyContracts`); a class named that is no implementation, a value that is no
  class name, or a binding that resolves to none throws `TenancyMisconfiguredException`. A `Membership` names its tenant
  by a non-blank opaque id, compared byte for byte, or none for a platform principal; a `MembershipSet` holds each
  tenant's membership, and a platform principal, once.
- SSO's `TenantMembership` requires its answer, read again inside the redeemer's transaction, to stay true until that
  commits, by a guard the writers of memberships take, and offers no other protection. So `Memberships::of()` takes the
  application's membership guard of the identity as it answers: a lock held until the asking transaction ends, by a
  locking read on the write connection (a shared lock on the identity's membership rows, or a lock on a guard row of
  its memberships). Every writer that revokes, expires or narrows a membership takes the same guard before it writes,
  and before it ends the person's sessions, so it waits for a redemption that read the membership to commit, and its
  clean-up finds the session that redemption wrote. SSO asks only once its own locks are held (the application's
  guards are seventh in its lock order) and such a writer takes none of SSO's locks, so the guard inverts no order.
  The adapters take no lock of their own: each asks `of()` inside SSO's transaction, so the guard is held there. A
  change that creates or accepts a membership reports it to SSO's scope widening first (IAM-7.3), whose identity guard
  is SSO's first lock; a provisioner guards only the new identity's own rows.
- `Tenancy\TenancySeams` binds, while `iam.adapters.sso` is on, over SSO's own defaults only, each transient. The rows
  answered from the memberships are never mandatory, since SSO's defaults fail closed; the tree's is mandatory while
  the application has a tree and SSO's enforcement is on (IAM-10.2), since SSO's default would then keep a tenant's
  enforcement from the tenants beneath it, so an application that keeps each tenant's rule to itself while it keeps a
  tree binds an inheritance of its own (decision recorded in `install-and-check.md`):

  | SSO seam                 | Bound to                        | Default replaced          | While                                  |
  | ------------------------ | ------------------------------- | ------------------------- | -------------------------------------- |
  | `TenantMembership`       | `TenantMembershipAdapter`       | `NoTenantMembership`      | memberships are named or bound         |
  | `LinkEligibility`        | `LinkEligibilityAdapter`        | `RefusingLinkEligibility` | memberships are named or bound         |
  | `PrincipalScope`         | `PrincipalScopeAdapter`         | `RefusingPrincipalScope`  | memberships are named or bound         |
  | `EnforcementInheritance` | `EnforcementInheritanceAdapter` | `OwnTenantInheritance`    | a tree is named or bound               |

  "Bound" means bound by the time every provider has registered. The binding rule runs as this package registers, and
  Laravel registers the application's own providers after the packages', so these four rows are applied once more from
  this package's booting callback, once every provider has registered and before any boots
  (`BindingRule::applyAgain()`, `IamServiceProvider::settle()`): memberships or a tree bound in an application
  provider's `register()` bind the adapters there, and the outcome kept for the checks gains them. So that only SSO's
  default is bound over then, each row the rule leaves off as it first runs is reserved (`BindingRule::reserve()`,
  from `IamServiceProvider::registerSeams()`): the exact binding of SSO's default the seam holds is recorded in the
  outcome, and where SSO has not registered yet, SSO's default is bound there first, shared, as SSO's `singletonIf()`
  would bind it, which SSO's own binding then leaves. Applied again, a row is bound only where the seam still holds
  exactly that binding. Anything bound over it meanwhile is the application's and is kept, even a binding of SSO's own
  default class, which by its class alone reads as SSO's: an application that keeps a tree for its own requirements
  and for the tree changes may bind `EnforcementInheritance` to `OwnTenantInheritance` in its `register()` to keep
  each tenant's SSO rule to itself, and it is kept, as it is with the tree named in configuration, where the first
  pass binds the adapter and the application's later binding replaces it. This runs only while `iam.adapters.sso` was
  on when the rule first read it, and the rows applied again follow the switch as it read then (`TenancySeams`'
  `ssoOn`), not as it reads by the booting phase, so the SSO seams and these rows are bound together or not at all: a
  provider registering after this package that turns the switch on or off comes too late for both. One bound from a
  provider's `boot()` binds none of these, though whatever it answers is asked by the adapters that are bound and by
  the revocations. Without memberships SSO keeps refusing: no membership, no `link`, a scope `unknown`.
- `TenantMembershipAdapter` answers the identity's membership of exactly the tenant asked, accepted at the time the
  person accepted it, and none for one not accepted, another tenant's, a platform principal or none.
  `LinkEligibilityAdapter` makes an identity eligible to `link` through a connection only by an accepted membership of
  exactly the connection's tenant: a `link` is the person's own act, so an invitation not taken up is not enough. An
  incomplete set answers for the memberships it holds, which are held whether it is complete or not.
- `PrincipalScopeAdapter` composes the membership half and the grant half (IAM-6.8): `within_tenant` only when both are,
  `outside_tenant` when either is, `unknown` otherwise. A complete set reaching beyond the tenant (a platform principal
  or any other tenant's membership) is `outside_tenant`; a complete set holding nothing else, none included, is
  `within_tenant`; an incomplete set is `unknown`, never `outside_tenant` on its own, since `outside_tenant` latches a
  verified domain link suspended for good. The grant half is this package's internal port
  `Tenancy\Contracts\GrantScope`, bound only while unbound: while `iam.adapters.authorization` is on, with `bindIf()`
  to `Authorization\GrantScopeAdapter`, which maps `laravel-authorization`'s grant scope query (AUTHZ-14.2,
  `GrantScopeQuery::forIdentity()`) `within`, `outside` and `unknown` onto SSO's verdicts, the identity named by its
  morph class and key and the tenant through `laravel-authentication`'s resolver
  (`Authorization\Translation\TenantTranslator`); with the switch off, with `singletonIf()` to `UnknownGrantScope`,
  which answers `unknown`, so nobody is `within_tenant` (Q9). It is asked only when the memberships leave the verdict
  open.
- The query answers `within` only for a complete list of the identity's principals, which `laravel-authorization`
  learns from its identity directory. Its default is complete only under its own subject resolver, never under this
  package's, so the package binds `Authorization\IdentityDirectoryAdapter` (a row of `AuthorizationSeams`, kept off
  while the application names its own directory in `authorization.identity_directory`): the principals the identity's
  `laravel-authentication` `principals()` relation lists, read on the write connection without the principal model's
  global scopes, complete. A principal a global scope hides (one
  soft-deleted, say) still holds its grants, and restoring it would widen the scope with no grant written and no grant
  hook run, so it is listed too; a relation that is no Eloquent query, whose scopes cannot be set aside, is answered
  incomplete. An identity that is itself a principal (`Principal`) and owns none acts as itself alone, complete and
  empty; one that is neither has its principals from a principal resolver the application binds to
  `laravel-authentication`, which no directory can list, and is answered incomplete, as is an identity it cannot
  resolve, as the contract asks. The same list makes the grant hook classify a grant by the identity's real principals
  rather than widen every one for want of it.
- A grant that widens an identity's scope reports it to SSO first (IAM-6.7) through `laravel-authorization`'s grant
  hook (`Authorization\GrantHookAdapter`, `AuthorizationSeams`, on while `iam.adapters.sso` is on too): inside the
  grant call's transaction, before `laravel-authorization` takes any lock, `ScopeWidenings::widen()` once for each
  distinct tenant the widening grants hold in (`null` for a platform-wide grant), with the client the widening carries
  (its operation's, none for trusted, console and queued work), after the hooks `authorization.grant_hooks` lists,
  which `laravel-authorization` runs first. The design of the hook, its lock order and its retries are in
  `authorization.md`.
- `EnforcementInheritanceAdapter` answers the nearest tenant, from the one asked up through the tree's ancestors, that
  has a rule, on or off, as IAM-7.5 words it (a stored version, `EnforcementService::get()->version`, SSO's own reader
  of what is stored, on the write connection, never `Enforcement::policy()`, which asks this contract), and the tenant
  itself when none has. A rule turned off keeps the question at its tenant; only a tenant never configured, with no row
  or only the unconfigured row SSO's `EnforcementLock` inserts, passes it up. So turning a rule off only ever loosens
  what applies to its tenant and to every tenant inheriting from it, and SSO's revoking nothing then leaves no session
  out of compliance; a tenant that stores its rule off opts out of its ancestors' rules, as a tenant that stores its own
  rule on replaces them. Who may change a tenant's rule is the application's authorisation, as SSO's
  `EnforcementService` says; an application that wants an ancestor's rule to bind every tenant below it refuses a
  descendant's change, or binds an enforcement inheritance of its own. A tree answering the tenant among its ancestors,
  one twice, or a blank id is a `LogicException`. The reads take no lock (see Failure / Edge Cases). The package never
  inherits a tenant MFA requirement (Q6).
- An enforcement change's revocation (`SessionRevocationAdapter`, scope `tenant`) and a reported tree change
  (`Tenancy\TreeChanges`) judge a whole subtree through `Tenancy\SubtreePolicyChanges`: the tenant first, then every
  descendant the tree answers, each once (a descendant answered twice is refused as a cycle as soon as the tree answers
  it, as an ancestor answered twice is, so a tree answering lazily never loops), each resolved through
  `laravel-authentication`'s tenant resolver before any is judged, and each judged with the strict cut-off of
  `laravel-authentication`'s `tenantPolicyChanged()`, as `TenantPolicyChanges` judges one tenant: once in place, and
  once more after the storage connection's transaction commits. The pass after the commit is one callback for the
  whole subtree, which lists and resolves the subtree again from the tree as it then stands, never the list the first
  pass read, so a tenant moved into the subtree while the change is open is judged by it (see Failure / Edge Cases).
  The enforcement change judges every descendant, a nearer tenant with a rule of its own among them: broader than the
  tenants that inherit, never narrower. Without a tree the subtree is the tenant.
- `Tenancy\TreeChanges::changed(string $tenantId): int` is the one core method an application calls when it moves a
  tenant, as `Iam::treeChanges()->changed($tenantId)`, inside the move's transaction and after the write, so the first
  pass judges the tree as moved before it commits. A removal is reported the same way: each child moved out from under
  the removed tenant, listed before the removal, is reported as moved once the restructure is written. While SSO's
  `enforcement` feature is on or a tenant MFA requirement is named or bound, it judges the tenant and its whole subtree
  (Q7); with neither it reads and judges nothing. It takes a plain id, reads no request, and keeps nothing (IAM-8.1).
  While `iam.adapters.authorization` is on and the application names or binds a tree, it first passes the change on to
  `laravel-authorization`, whatever enforcement says. While the SSO adapters are on too
  (`AuthorizationSeams::reportsWidenings()`), every identity holding a live grant rooted at the moved tenant or below
  it (`Authorization\SubtreeGrantees`: `laravel-authorization`'s role, permission and policy grants, read on its
  connection under the names its own `Config\TableNames` gives the tables, a principal's grant answering its identity,
  a subtree holding a tenant of another type refused so the move rolls back) is reported to SSO's scope widening in the
  moved tenant (`ScopeWidenings::widen()`), in the move's transaction, every one's identity guard taken first, in SSO's
  order (`Sso\IdentityGuards`), so the move never takes a guard after a connection: the grant half counts a grant below
  a tenant within it, so a move out from under a linked tenant widens the person's scope with no grant written, and no
  grant hook runs. The package cannot tell such a move from one within the tenant, so this is broader than needed, never
  narrower: a link in a tenant the subtree still stands below is suspended too, latched, and is linked again. Then the
  move is reported to `laravel-authorization` (`Authorization::treeChanged()`, AUTHZ-12.8), the moved tenant named
  through the resolver (`TenantTranslator`): one report covers the subtree, since `laravel-authorization`'s entries pin
  the tenant chain. Without a tree `laravel-authorization` keeps its own flat tree, which no move changes, and nothing
  is reported.
- `laravel-authorization`'s tree is the application's one tree (IAM-7.5): `Authorization\TenantTreeAdapter`, a row of
  `AuthorizationSeams`, scoped, one for a request or job (`authorization.md`), answers
  the ancestors, containment and subtree from `TenancyContracts::tree()` on every call. Each tenant asked about must
  resolve back through the tenant resolver to a tenant of its type and key (`TenantTranslator::idOf()`,
  `UnresolvedReferenceException` otherwise), each ancestor is named as the resolver names its id, and the subtree is
  nested in a query on the tree's own connection that adds the asked tenant's type as `tenant_type`, and selects each
  id as text in the connection's grammar, so a tree over integer keys is compared with `laravel-authorization`'s text
  columns, which PostgreSQL otherwise refuses. Every tenant of the tree must be of one type: the application's subtree
  selects ids alone, so a tenant below of another type would be named by the wrong type and match none of its grants,
  which the grant scope query reads as rooted elsewhere, `outside`, not as a narrower answer. So a tree that places a
  tenant below one of another type is refused (`TenancyMisconfiguredException::forMixedTree()`) wherever the package
  meets it: `ancestors()` refuses an ancestor of another type, so every check in such a tenant refuses;
  `TenantTreeAdapter::tenantsIn()` lists a subtree's tenants through the resolver and refuses one of another type, and
  confirms every `outside` answer the grant half gives (`GrantScopeAdapter`) and lists a moved subtree's grantees
  (`SubtreeGrantees`), so neither suspends a link, nor leaves one standing, on a subtree read by the wrong type.
  `isWithin()` answers `false` for two tenants of different types, as the subtree does. `iam:check` cannot tell such a
  tree, since the tree contract lists no tenants without a tenant to start from. The row is bound
  whether or not the application has a tree, through a factory (`TenantTreeAdapter::forApplication()`) that builds the
  adapter while the application names or binds a tree and `laravel-authorization`'s own `FlatTenantTree` otherwise,
  decided as each request or job first resolves the scoped seam: `laravel-authorization` tells a flat application by
  that class, never by a tree's answers, and takes any other down its hierarchical paths, so a flat application would
  have `whereAuthorized()` refused on a model kept off the storage connection. None of the reserve and apply-again
  machinery the SSO tenancy rows need applies to it, and a tree bound later is read from the next unit of work. The
  adapter, asked with no tree, throws `TenancyMisconfiguredException`. `iam:check` refuses `ResolveNoTenant` while the
  authorization adapters are on beside a tree, as every tenant the tree is asked about resolves through it.
- The provider's groups (IAM-7.2) map to grants through the application's `Contracts\GroupMapping`
  (`grantsFor($connectionId, $tenantId, $groups)`, answering `Provisioning\GrantInstruction`s), found by
  `Provisioning\GroupSettings`: the binding, else the class `iam.provisioning.groups.mapping` names, else, while
  `iam.provisioning.groups.map` maps any group, `Provisioning\ConfiguredGroupMapping`. A `GrantInstruction` is a role
  and whether it reaches the tenants below; it names no tenant, application or expiry, so a connection's groups never
  grant beyond its tenant and its subtree. The listener asks the mapping once the link is created, after every lock of
  SSO's, and `Provisioning\GroupGrants::grant()` grants each role to the new identity in the connection's tenant
  through `laravel-authorization`'s `GrantService`, as trusted system work, in a savepoint of the listener's
  transaction; the grant hook reports the widening again, finding the identity's guard held and nothing to suspend.
- The re-sync (IAM-7.2) is the application's opt-in, `Contracts\GroupResync`
  (`resync($identity, $connectionId, $tenantId, $groups)`), found by `GroupSettings` from the binding or
  `iam.provisioning.groups.resync`. `Sso\SignInRedemption` calls it for every redeemed `sign_in` that links an identity
  and signs it in, once the redemption's transaction has committed, in a transaction of its own through the retry
  helper, and before the credential is handed out: a re-synced grant that widens reports to SSO's scope widening, which
  takes the identity's guard, and SSO's lock order puts the guard before the connection, the code and the link the
  redemption locked, so the re-sync never runs under them. Grants are read on every check, so nothing in the session
  depends on their being written first, and no request acts on the session before the re-sync commits. A refusal
  propagates once the sign-in has committed: the code is spent and the session written is never handed out.
  `Provisioning\MappedGroupResync`, shipped for the application to name, makes the
  identity's own roles in the tenant exactly the mapping's (`GroupGrants::sync()`: `syncRoles()` in the tenant, then
  each role's reach), and refuses with no mapping rather than revoke every role.
- Every action has one public core method taking plain values, and none takes a request: the listener answers from
  SSO's event alone; `widen()` takes an identity, a tenant id or none, and `laravel-authentication`'s `ClientContext`,
  which a controller builds with `ClientContext::fromRequest()` and a job as `new ClientContext(null, null)`;
  `changed()` takes a tenant id. Both services are reached through the manager's accessors
  (`Iam::scopeWidenings()`, `Iam::treeChanges()`), as `Iam::tenantPolicies()` is, never through a second, flattened
  method of the manager's repeating them (the plan's `Iam::widenScope()` and `Iam::treeChanged()`). No adapter reads
  the current request, the current user or a guard's current session: each resolves the identity SSO names through the
  morph map (`IdentityReferences`) and the tenant through `laravel-authentication`'s tenant resolver.
- The provisioner, the memberships, the tree and the tenant MFA requirement are each found the same way
  (`Bindings\ConfiguredImplementations`): the application's binding first, then the class named, each failure throwing
  the contract's own exception (`Bindings\Contracts\ReportsMisconfiguration`).
- Decisions this note records, beyond the plan's: the transaction is attempted once (the grant's claim survives a
  rollback); an identity whose insertion during the call was not witnessed is refused (the grant proves authority, not
  newness, and `wasRecentlyCreated` alone outlives the call); `createMembership()` answers nothing, since the group
  mapping grants to the identity itself; provisioning is checked at each dispatch, not at registration, and is
  independent of `iam.adapters.sso`; an invitation not accepted is not eligible to `link`; an incomplete set is
  `unknown`, never `outside_tenant`; the inheritance reads take no lock; the nearest tenant with a rule, on or off,
  enforces, as IAM-7.5 words it, so a rule turned off only loosens and needs no revocation, rather than the nearest
  whose rule is on, which would move the tenants below a rule turned off onto a stricter ancestor's rule with nothing
  revoking the sessions that rule refuses (SSO revokes only for a rule turned on); the tenancy rows are applied once
  more once every provider has registered, so an application provider's `register()` binds them; an insertion is also
  witnessed through the identity model's own `created` event, which may stand in for Eloquent's; the memberships kit
  checks that a complete set holds every principal the identity holds; an enforcement change judges every descendant,
  not only those that inherit; a removal is reported after it is written, as the move of each child moved out from under
  the removed tenant; the tree's contract kit checks the descendants and the subtree against the tenants the test case
  knows are below, not the tree's own answer; the tree's ids are opaque strings, as SSO and `laravel-authentication`
  name tenants, not `laravel-authorization`'s `Reference`; `GrantScope` lives in `Tenancy\Contracts`, as the house rule
  puts every interface in a `Contracts` namespace; a subtree's pass after the commit lists the subtree again rather than
  judge the tenants its first pass listed; and the end-to-end domain reservation test binds a grant scope answering
  `within_tenant`, since nothing shipped can; the memberships take the application's membership guard as they answer,
  and every writer that narrows a membership takes it too, since SSO's tenant membership offers no other protection (the
  plan's memberships took no lock); the listener's one attempt reads committed rows on PostgreSQL, MySQL and MariaDB,
  rather than keep the connection's level and end a sign-in as a server error whenever another link commits in the
  connection meanwhile (PostgreSQL) or another first sign-in, `link` or reservation inserts a link into the same gap of
  the links' identity index (MySQL and MariaDB); the seams answered from the memberships and the tree are bound, once
  every provider has registered, only over the very binding of SSO's default reserved as the rule first ran, never over
  a binding the application made of SSO's own default class; and a descendant answered twice is refused as a cycle, not
  listed once.

## Success Path

1. A `sign_in` resolves to no identity and holds no reservation. SSO issues a grant, registers it to the dispatch and
   dispatches `ResultUnlinked` synchronously, with no transaction of its own open.
2. The listener asks `ProvisioningSettings` for the provisioner, opens its transaction, and writes the identity, the
   widening, the membership and the link in that order. The helper answers `created`; the transaction commits, and
   SSO reports `LinkCreated` (`provisioning`) after that commit.
3. SSO's final continuation takes its locks again, resolves the link anew, and issues the handoff bound to it
   (`HandoffIssued`). The application redeems it through `Iam::signIns()->redeem(...)`, and the new person is signed
   in through the link.
4. A change of the application's own that gives a person a principal opens a transaction on the storage connection
   (`Iam::transaction()`), calls `Iam::scopeWidenings()->widen($identity, $tenantId, $client)` first, takes its own
   guard of the person's principals, writes the principal and commits. SSO suspends the person's links by a verified
   domain in every other tenant's connection, deletes their reservations there and revokes the sessions established
   through each in that transaction (`linkScopeWidened()`, whatever any setting says); a second report suspends and
   revokes nothing more.

5. A member links through a connection of their tenant: SSO asks `LinkEligibilityAdapter` at the completion and again
   inside the standalone redemption, and the person's accepted membership makes them eligible; anyone else is
   `link_ineligible`.
6. A member who accepted before the tenant's domain was verified, holding no membership and no grant beyond the
   tenant (`laravel-authorization`'s grant scope query answers `within`), signs in for the first time by a verified
   email of that domain: the completion reserves a link, and `Iam::signIns()->redeem(...)` activates it with verified
   domain provenance and signs the person in through it.
7. An administrator turns a tenant's rule on. SSO locks that tenant's row and asks the revocation for it; the adapter
   judges the sessions of the tenant and of every tenant below it in the tree, in SSO's transaction and once more after
   it commits, so a session in any of them the rule no longer allows ends. Turned off again, the rule stays its tenant's
   and requires nothing, so the tenant and every tenant inheriting from it require nothing, whatever an ancestor's rule
   requires, and nothing needs revoking.
8. The application moves a tenant under an enforcing ancestor and reports it inside the move's transaction;
   `laravel-authorization` drops the resolutions built in the moved tenant and below it, and the moved tenant's
   sessions and its subtree's are judged against the rule they now inherit.
9. A first sign-in reports groups the mapping maps: the listener grants their roles to the new identity in the
   connection's tenant once the link is made, and commits them with it. With the re-sync named, a later sign-in
   reporting other groups grants the roles of a group added and revokes those of a group removed once the sign-in
   commits, before its credential is handed out.

## Failure / Edge Cases

- **An identity that is not new.** An identity found, one inserted before the call and kept, a fresh instance of the
  row, or one inserted quietly (`createQuietly()`, `saveQuietly()`, `withoutEvents()`) is not witnessed as inserted by
  the call. The listener refuses it with a `LogicException` before the widening, the membership or the link; the
  transaction rolls back and the completion ends as a server error. The existing identity is left as it was. An
  identity model that declares a `created` event of its own is witnessed through it when the event keeps the model in
  a property, as Eloquent builds it around the model; one that keeps no model, while a listener of it answers a value
  (which makes Eloquent skip its own `created` event), hides a new identity, which is refused the same way
  (`Contracts\Provisioner` says so).
- **The helper refuses** (`request_unavailable`, `expired`, `subject_already_linked`, `link_limit_reached`, a grant
  refused). A refusal wrote nothing; the listener throws its internal `RefusedLink` inside the transaction so the
  identity and the membership roll back with it, catches it once the transaction has rolled back, and returns. SSO's
  final step finds the result still unlinked and ends the flow with its reason.
- **Anything thrown** by the provisioner, the widening, the helper or the database rolls every write back and
  propagates: SSO ends the completion as a server error, the request stays consumed, and the person starts a new flow.
  A serialisation failure or a deadlock is not retried (the grant is spent); the attempt reads committed rows on
  PostgreSQL so that a link committed meanwhile is not one.
- **The subject linked elsewhere meanwhile.** Another request that links the same subject through SSO, raising the
  connection's `links_version`, and commits while the listener runs is found by the helper's locked read of the
  subject's link, on every supported engine and level, PostgreSQL's REPEATABLE READ included, since the attempt reads
  committed rows there: `subject_already_linked`, so the listener's identity and membership roll back, and the
  completion resolves the subject anew and hands off for the identity the other link names.
- **Another subject linked meanwhile.** Another person's first sign-in through the same connection that commits its
  link while the listener runs leaves the provisioning as it was, on every supported engine and level: the helper's
  locked read of the connection waits for that commit and reads it, rather than fail to serialise on PostgreSQL at
  REPEATABLE READ.
- **A later completion failure** (the connection disabled before the final step, a deadline passed) does not undo what
  the listener committed: the identity, its membership and the link stay made, and the next sign-in through the
  connection resolves through the link without being offered for provisioning again.
- **A second provisioning listener**, the application's own, shares the one grant and is refused `grant_invalid`.
  Register none beside the package's while a provisioner is configured; with none configured, the application's own
  listener is the only one that provisions.
- **A queued listener** fails loudly: the event refuses to be serialised, so queuing it throws, and nothing is
  provisioned.
- **A widening outside a transaction** is SSO's `LogicException`, with nothing suspended or revoked. A widening whose
  revocation throws rolls back to its savepoint, so a caller that catches the failure and commits keeps no suspension;
  the caller's own rollback undoes it too. SSO's `LinkCandidatesChanged` and a serialisation failure reach the caller
  as its own retry recognises them, and are retried only as its whole transaction. An identity that is no Eloquent
  model throws `UnresolvedReferenceException` before anything is locked (IAM-8.2).
- **Provisioning with `iam.adapters.sso` off.** The listener still provisions once a provisioner is configured;
  SSO's helper then needs the application's linker to be backed by `Contracts\LinkStorage`, or it is SSO's
  `LogicException` with nothing written.

- **A membership revoked during a redemption.** A writer revoking a membership that a redemption (a reservation's
  activation, a `link`, a sign-in through a verified domain link) has read waits on the membership guard until the
  redemption commits; its clean-up then finds the session the redemption wrote and ends it, and the next resolution of
  the link finds no membership. A writer that takes no guard, or memberships that take none, let the revocation commit
  first and its clean-up miss the session, leaving a non-member with a verified domain link and a live session in the
  tenant. A revocation that commits before the redemption reads is seen by it: on MySQL, and at READ COMMITTED, the
  locking read reads the revocation; on PostgreSQL at REPEATABLE READ it fails to serialise and the redemption's
  transaction is retried whole.
- **No accepted membership.** `TenantMembership` answers none and `LinkEligibility` ineligible for an invitation not
  taken up, another tenant's membership, a platform principal or none; SSO then reserves nothing (the sign-in goes on
  as `unlinked`) or refuses a `link` as `link_ineligible`. An identity reference that names nobody throws
  `UnresolvedReferenceException`, memberships that cannot be read throw their failure, and an adapter asked with no
  memberships configured throws `TenancyMisconfiguredException`, each inside SSO's transaction (IAM-8.2).
- **A person reaching beyond the tenant.** Once the adapters are bound over SSO's default, which answers `unknown`, a
  verified domain link whose person holds another tenant's membership or a platform principal is judged
  `outside_tenant` at its next resolution: SSO latches it suspended for good and revokes its sessions. A change that
  gives the person that principal should have reported it first (`Iam::scopeWidenings()`), which suspends the link at
  once; the resolution catches one that did not.
- **A rule turned off under an enforcing ancestor.** The tenant keeps its own rule, now requiring nothing, and so does
  every tenant inheriting from it: none moves onto the ancestor's rule. Every session there complies, as SSO's revoking
  nothing for a rule turned off assumes, and a password sign-in there signs in. The ancestor's rule still applies to
  the ancestor and to every tenant below it with no rule of its own. A tenant whose administrators should never opt out
  of an ancestor's rule is the application's to protect, by refusing the change.
- **An ancestor's rule turned on during a descendant's admission.** The inheritance reads take no lock: SSO locks only
  the enforcing tenant's row, and a change of a rule judges its subtree's sessions while holding its own tenant's row,
  so a locking read of the path would invert that order against an admission and deadlock. Inside a transaction that
  has already read, at REPEATABLE READ, the rules are read as of its snapshot. So an admission in a descendant may judge
  an ancestor's rule as it was; its session is revoked by the change, in place or by the second pass, when it commits
  before that pass runs, and judged at its first refresh when it commits after. A password sign-in racing the change
  is caught the same way, as in `tenant-authentication-policy.md`.
- **A tenant moved while an ancestor's rule is turned on.** A change of a rule lists its tenant's subtree as its first
  pass starts, and a move reported on another connection while the change is open reads the ancestor's rule without a
  lock, as it was before the change: neither the move's passes nor the change's first pass judge the moved tenant
  under the rule. So the change's pass after its commit lists the subtree again, finds the moved tenant, and judges
  its sessions against the rule that has committed; when the move commits after the change, its own pass after its
  commit reads the committed rule. Of the two, whichever commits last judges the moved tenant against both, and a
  session the rule refuses is revoked as the later commits. A session already recorded at the version a pass answers
  is skipped, so judging a tenant again costs a read. What that pass throws, a subtree tenant that can no longer be
  resolved or a tree that cannot be read, propagates from the commit, the change already durable.
- **A broken or unreadable tree.** A cycle, a repeated or a blank id is a `LogicException`; a tree that throws
  propagates; a tenant of the subtree the tenant resolver cannot resolve throws `UnresolvedReferenceException` before
  any tenant is judged. Inside SSO's change or the application's move, each rolls the change back with every session
  standing.
- **A removed tenant.** Once it is removed it can no longer be resolved, nor its subtree listed, so the application
  lists its children before removing it and, once the restructure is written, inside the same transaction, reports
  each as moved. The children are judged against the structure that will commit, in place; a report made before the
  write would judge the old tree and leave a child moved under a stricter ancestor to the pass after the commit. The
  removed tenant's own sessions, and those of any tenant removed with it, are `laravel-authentication`'s
  `tenantDeactivated()`'s.
- **A tree bound late.** One bound in an application provider's `register()` binds the inheritance adapter from the
  booting callback. One bound only from a provider's `boot()` binds no inheritance adapter: SSO's default stays and
  each tenant's rule applies to it alone, while the revocations still judge the subtree the tree answers. Bind the tree
  in `register()`, or name it. An application that binds an enforcement inheritance of its own with no tree configured
  leaves the tenants that inherit unjudged by an enforcement change.
- Gaps in the members that the adapters work around:
  - `laravel-authorization`'s `Reference` names a tenant by a morph type and a key, while the tree, SSO and
    `laravel-authentication` name it by an opaque id; the package takes the key for the id (`TenantTranslator`) only
    once it resolves back to the same tenant, so a tenant whose key is not its identifier is refused wherever it is
    named, a grant in it included. A tenant reference that carried its identifier would close it.
  - `laravel-sso`'s `DatabaseEnforcement::lock()` locks only the enforcing tenant's rule, and a change of a rule only
    its own tenant's row, so no lock spans the inheritance path and an inheritance answer may be read as of a snapshot.
    Letting `EnforcementInheritance` answer the path, nearest first, and locking every row on it from the root down in
    the admission and the change would close it.
  - `laravel-sso`'s `RevocationScope::tenant()` names only the enforcing tenant, so the tenants that inherit come from
    this package's tree; an inheritance of the application's own with no tree leaves them unjudged.
  - `laravel-sso`'s `ProvisioningGrant::claim()` marks the grant used in memory, which a rollback does not undo, so the
    listener's transaction cannot be retried after a concurrency failure and the person starts a new flow.
  - `laravel-sso`'s guide for this package shows `ProvisioningHelper::link()` with three arguments; it takes a fourth,
    the `ClientContext`, which the listener builds from the event's context.
  - `laravel-sso`'s `ProvisioningHelper` does not say that, on PostgreSQL at REPEATABLE READ, any link committed in the
    connection after the listener's snapshot (another person's or the same subject's: each raises `links_version`)
    fails its locking read of the connection to serialise, nor that, at InnoDB's REPEATABLE READ, the scope widening
    its guide puts first gap-locks the new identity's empty range of the links' identity index before the helper
    takes the rule and the connection, which deadlocks two first sign-ins at once; the spent grant can retry neither,
    so the listener reads committed rows on PostgreSQL, MySQL and MariaDB for it.
  - `laravel-sso` ships no contract kit for `TenantMembership`, `LinkEligibility`, `PrincipalScope` or
    `EnforcementInheritance`, so IAM-8.3 has none to extend here; `laravel-authentication` has no identity-creation
    contract, so the provisioner is the application's own.

## Implementation Anchors

- `src/Contracts/Provisioner.php`; `src/Provisioning/ProvisioningSettings.php`: `provisioner()`, `KEY`;
  `src/Exceptions/ProvisionerMisconfiguredException.php`: `forClass()`, `forValue()`, `forBinding()`;
  `config/iam.php`: `provisioning.provisioner`.
- `src/Provisioning/ProvisionOnUnlinkedResult.php`: `listen()`, `handle()`, `ATTEMPTS`;
  `src/Provisioning/CommittedReads.php`: `beforeBeginning()`, `onceBegun()`, `STATEMENT`;
  `src/Provisioning/InsertionWitness.php`: `witness()`; `src/Provisioning/RefusedLink.php`;
  `src/IamServiceProvider.php`: `boot()`.
- `src/Tenancy/ScopeWidenings.php`: `widen()`; `src/IamManager.php`: `scopeWidenings()`; `src/Facades/Iam.php`;
  `src/Sso/IdentityReferences.php`: `reference()`; `src/Sso/Translation/ClientTranslator.php`: `toSso()`;
  `src/Transactions/CrossMemberTransaction.php`: `run()`.
- `src/Testing/FakeProvisioner.php`: `fake()`, `refuseIdentities()`, `refuseMemberships()`, `identities()`,
  `memberships()`; `src/Testing/Seams/ProvisionerContract.php`; `src/Testing/Seams/Concerns/ProvisionerTests.php`.

- `src/Contracts/Memberships.php`; `src/Contracts/TenantTree.php`: `ID_COLUMN`; `src/Tenancy/Membership.php`;
  `src/Tenancy/MembershipSet.php`: `in()`, `reachesBeyond()`, `isComplete()`; `src/Tenancy/TenancyContracts.php`:
  `memberships()`, `tree()`, `hasMemberships()`, `hasTree()`, `MEMBERSHIPS`, `TREE`;
  `src/Exceptions/TenancyMisconfiguredException.php`; `config/iam.php`: `tenancy.memberships`, `tenancy.tree`;
  `src/Bindings/ConfiguredImplementations.php`: `find()`, `isConfigured()`, `isNamed()`;
  `src/Bindings/Contracts/ReportsMisconfiguration.php`.
- `src/Tenancy/TenancySeams.php`: `seams()`; `src/Tenancy/IdentityMemberships.php`: `identity()`, `of()`;
  `src/Tenancy/TenantMembershipAdapter.php`: `standing()`; `src/Tenancy/LinkEligibilityAdapter.php`: `judge()`;
  `src/Tenancy/PrincipalScopeAdapter.php`: `judge()`; `src/Tenancy/Contracts/GrantScope.php`;
  `src/Tenancy/UnknownGrantScope.php`; `src/IamServiceProvider.php`: `registerSeams()`, `settle()`;
  `src/Bindings/BindingRule.php`: `reserve()`, `applyAgain()`; `src/Bindings/BindingOutcome.php`;
  `src/Bindings/MemberDefaults.php`: `bindingOf()`.
- `src/Tenancy/EnforcementInheritanceAdapter.php`: `enforcingTenant()`; `src/Tenancy/SubtreePolicyChanges.php`:
  `changed()`; `src/Sso/SessionRevocationAdapter.php`: `revoke()`; `src/Tenancy/TreeChanges.php`: `changed()`;
  `src/IamManager.php`: `treeChanges()`.
- `src/Authorization/GrantScopeAdapter.php`: `judge()`, `outside()`; `src/Authorization/IdentityDirectoryAdapter.php`:
  `principalsOf()`, `unscoped()`; `src/Authorization/TenantTreeAdapter.php`: `ancestors()`, `isWithin()`, `subtree()`,
  `tenantsIn()`, `forApplication()`; `src/Exceptions/TenancyMisconfiguredException.php`: `forMixedTree()`;
  `src/Authorization/SubtreeGrantees.php`: `of()`; `src/Sso/IdentityGuards.php`: `acquire()`;
  `src/Authorization/GrantHookAdapter.php`: `beforeWidening()`; `src/Authorization/Translation/TenantTranslator.php`:
  `toReference()`, `idOf()`; `src/Authorization/AuthorizationSeams.php`: `seams()`, `DOMAIN_LINKING`.
- `src/Contracts/GroupMapping.php`; `src/Contracts/GroupResync.php`; `src/Provisioning/GrantInstruction.php`:
  `role()`, `roleWithSubtree()`, `MAX_ROLE_LENGTH`; `src/Provisioning/GroupSettings.php`: `mapping()`, `resync()`,
  `MAPPING`, `MAP`, `RESYNC`; `src/Provisioning/ConfiguredGroupMapping.php`: `grantsFor()`;
  `src/Provisioning/GroupGrants.php`: `grant()`, `sync()`, `groupsOf()`; `src/Provisioning/MappedGroupResync.php`:
  `resync()`; `src/Exceptions/GroupMappingMisconfiguredException.php`: `forMap()`, `forNoMapping()`;
  `src/Sso/SignInRedemption.php`: `redeem()`, `resync()`; `config/iam.php`: `provisioning.groups`.
- `src/Testing/FakeGroupMapping.php`: `fake()`, `map()`, `refuse()`, `asked()`;
  `src/Testing/Seams/GroupMappingContract.php`; `src/Testing/Seams/Concerns/GroupMappingTests.php`.
- `src/Testing/FakeMemberships.php`, `src/Testing/FakeTenantTree.php`; `src/Testing/Seams/MembershipsContract.php`:
  `assertAnswersEveryPrincipal()`, `src/Testing/Seams/TenantTreeContract.php`;
  `src/Testing/Seams/Concerns/MembershipsTests.php`, `src/Testing/Seams/Concerns/TenantTreeTests.php`.

## Authoritative Tests

- `tests/Integration/Provisioning/ProvisionOnUnlinkedResultTest.php`: at the connection's own level on SQLite, MySQL and
  PostgreSQL, then at READ COMMITTED and REPEATABLE READ on MySQL and PostgreSQL,
  `testAnUnlinkedSignInIsProvisionedAndSignsTheNewPersonIn`, `testEachWriteComesInOrderInsideOneTransaction`,
  `testAnExistingIdentityIsNeverProvisioned`, `testAnIdentityInsertedBeforeTheCallIsNeverProvisioned`,
  `testARefusedLinkRollsBackTheIdentityAndTheMembership`, `testAnExceptionRollsBackEveryWrite`,
  `testTheGrantIsUsedOnce`, `testWhatTheListenerCommittedStandsAfterALaterFailure` (the membership row read back),
  `testTheWideningIsReportedForTheCompletionsClient` (the suspension's IP address and user agent the completion's); at
  READ COMMITTED and REPEATABLE READ on MySQL and PostgreSQL only, since SQLite's single writer cannot commit a second
  connection's link while the listener's transaction is open,
  `testASubjectLinkedElsewhereMeanwhileLeavesNoProvisionedPerson`, `testAnotherSubjectLinkedMeanwhileStillProvisions`
  (the other link made through SSO's `LinkStorage::create()`, which raises `links_version`, committed on a second
  database connection, through the same SSO connection, once the listener has inserted its person),
  `testTheAttemptReadsCommittedRows` (the level the transaction itself reports, and the connection's own level left as
  it was); and at the connection's own level alone, where no level changes what is
  read, `testTheTransactionIsNeverRetried` (the serialisation failure simulated),
  `testAQueuedListenerFailsLoudlyAndProvisionsNothing`, `testWithNoProvisionerNothingIsProvisioned`,
  `testAuthenticationsUnlinkedResultProvisionsNothing`, `testWithTheSsoAdaptersOffTheHelpersRefusalWritesNothing`
  (`iam.adapters.sso` off, a provisioner configured: SSO's `LogicException`, no row written), and on every engine
  `testTheAttemptIsSetBeforeAnythingIsWritten` (the setting recorded with the transaction level it is made at: inside
  the listener's transaction on PostgreSQL, with none open on MySQL and MariaDB);
  `tests/Integration/Provisioning/ConcurrentProvisioningTest.php` `testTwoFirstSignInsAtOnceAreBothProvisioned` (MySQL
  and PostgreSQL at READ COMMITTED and REPEATABLE READ: the first listener held open past the widening while a forked
  worker provisions a second subject's person on a second database connection, from its start to its commit, and both
  are provisioned; at MySQL's REPEATABLE READ without the committed reads, the worker's link insert waits on the first
  listener's gap lock and the first listener's lock of the connection then deadlocks);
  `tests/Integration/Provisioning/InsertionWitnessTest.php` `testAnInstanceInsertedDuringTheCallIsWitnessed`,
  `testNoOtherAnswerIsWitnessed`, `testOnlyTheInsertionOfTheAnswerVouchesForIt`,
  `testAnInsertionAnnouncedByTheModelsOwnEventIsWitnessed`, `testOnlyTheModelsOwnCreatedEventVouchesForIt`,
  `testAnEventThatIsNeitherANameNorAnObjectVouchesForNothing`, `testEloquentsDispatcherIsPutBackHoweverTheCallEnds`,
  `testWithoutADispatcherNothingIsWitnessed`, `testEveryCallGoesOnToEloquentsDispatcher`
- `tests/Feature/Provisioning/ProvisioningListenerTest.php` `testTheListenerIsRegisteredOnSsosEvent`,
  `testWithNoProvisionerTheListenerDoesNothing`, `testAProvisionerBoundOnceBootedIsAsked`,
  `testAnIdentityThatIsNoModelIsRefused`, `testTheSandboxsProvisionerIsAsked`;
  `tests/Unit/Provisioning/RefusedLinkTest.php` `testTheRefusalCarriesTheAnswerAndNamesItsStatus`;
  `tests/Unit/Provisioning/CommittedReadsTest.php` `testTheListenersNextTransactionOnMysqlReadsCommittedRows`,
  `testTheListenersOwnTransactionOnPostgresReadsCommittedRows`, `testNothingElseIsSetBeforeBeginning`,
  `testNothingElseIsSetOnceBegun`
- `tests/Unit/Provisioning/ProvisioningSettingsTest.php` `testWithNoProvisionerProvisioningIsOff`,
  `testTheClassNamedIsBuilt`, `testTheApplicationsBindingWinsOverTheClassNamed`,
  `testTheProvisionerIsTheOneBoundWhenAsked`, `testAClassNamedThatIsNoProvisionerFailsClosed`,
  `testAValueThatIsNoClassNameFailsClosed`, `testABindingThatResolvesToNoProvisionerFailsClosed`
- `tests/Integration/Tenancy/ScopeWideningsTest.php`, at the connection's own level on every engine, then at READ
  COMMITTED and REPEATABLE READ on MySQL and PostgreSQL,
  `testAPrincipalOfAnotherTenantSuspendsTheLinkAndRevokesItsSessions`, `testAPlatformPrincipalSuspendsTheLink` (each
  suspension reported with the caller's client's IP address and user agent), `testAClientWithNothingKnownIsReportedSo`
  (a job's or a command's client, its suspension reported with neither),
  `testAPrincipalOfTheLinksOwnTenantLeavesItAlone`, `testItRollsBackWithTheCallersTransaction`,
  `testARevocationThatThrowsLeavesNoSuspension`; and at the connection's own level alone, since each is refused before
  anything is read or locked, `testOutsideATransactionItIsRefused` and `testAnIdentityThatCannotBeNamedThrows`;
  `tests/Feature/IamManagerTest.php` `testTheScopeWideningsAreReachedThroughTheirOwnService`
- `tests/Feature/Bindings/BindingRuleTest.php` `testApplyingAgainDecidesOnlyWhatTheOutcomeLeftOpen`,
  `testReservingRecordsTheMembersDefaultEachSeamHolds`, `testABindingMadeOverAReservedSeamIsKept`
- `tests/Unit/Testing/FakeProvisionerTest.php` (this package's `ProvisionerTests`)
  `testProvisionerCreatesANewIdentity`, `testProvisionerNeverAnswersAnExistingIdentity`,
  `testProvisionerCreatesTheNewIdentitysMembership`, `testProvisionerRefusesByThrowing`,
  `testTheKitFailsAnIdentityItDidNotInsert`, `testTheKitFailsTheSameIdentityTwice`,
  `testTheKitFailsAnExistingIdentity`, `testTheKitFailsAProvisionerThatCreatesNoMembership`,
  `testTheKitFailsAMembershipThatWasThereBefore`, `testTheKitsCheckFailsAProvisionerAnsweringTheExistingIdentity`,
  `testEveryCheckOfTheKitIsAPublicTest`
- `tests/Performance/Provisioning/ProvisioningQueryBudgetTest.php` `testAProvisionedSignIn`, `testNoProvisioner`

- `tests/Unit/Tenancy/MembershipTest.php` `testAnAcceptedMembershipOfATenant`, `testAPlatformPrincipalIsOfNoTenant`,
  `testABlankTenantIsRefused`; `tests/Unit/Tenancy/MembershipSetTest.php`
  `testTheMembershipOfExactlyTheTenantIsFound`, `testASetReachesBeyondATenantThroughAnyOtherMembership`,
  `testASetHoldsEachMembershipOnce`; `tests/Unit/Tenancy/UnknownGrantScopeTest.php`
  `testEveryIdentitysGrantsAreUnknown`; `tests/Unit/Tenancy/TenancyContractsTest.php`
  `testTheApplicationsBindingWins`, `testAValueThatIsNoClassNameFailsClosed`,
  `testAClassThatIsNoImplementationFailsClosed`, `testABindingThatResolvesToNoImplementationFailsClosed`
- `tests/Feature/Tenancy/TenancySeamsTest.php` `testWithoutMembershipsOrATreeSsosDefaultsStay`,
  `testMembershipsNamedBindTheMembershipAdapters`, `testATreeNamedBindsTheInheritanceAdapter`,
  `testMembershipsAndATreeBoundBeforeRegisteringBindTheAdaptersInEveryProviderOrder`,
  `testMembershipsAndATreeBoundAfterRegisteringBindTheAdapters`,
  `testAnApplicationProviderBindingTenancyWhileRegisteringBindsTheAdapters` (an application provider registered after
  every package provider, in every order of theirs), `testAnApplicationsOwnBindingMadeAfterRegisteringIsKept`,
  `testAnApplicationsBindingOfSsosDefaultClassMadeWithItsTenancyIsKept` (SSO's own default classes bound in the
  application's `register()` beside its memberships and tree, in every provider order),
  `testMembershipsAndATreeBoundWhileBootingBindNothing`, `testWithTheSsoSwitchOffTenancyBoundLaterBindsNothing`,
  `testTheSsoSwitchTurnedOnAfterRegisteringBindsNoTenancy`,
  `testTheSsoSwitchTurnedOffAfterRegisteringStillBindsTheTenancy`,
  `testTheTenancyRowsFollowTheSwitchAsItReadWhenGivenIt`, `testTheApplicationsOwnBindingsAreKept`,
  `testTheTenancyRowsAreTransientOverSsosDefaults`, `testTheGrantScopeIsAuthorizationsQueryUntilTheApplicationBindsOne`;
  `tests/Feature/IamServiceProviderTest.php` `testTheGrantScopeIsAuthorizationsQueryUntilSomethingElseIsBound`,
  `testTheGrantScopeIsUnknownWithTheAuthorizationSwitchOff`
- `tests/Feature/Authorization/GrantSeamsTest.php` `testEveryAdapterIsBoundOverItsMembersDefaultInEveryProviderOrder`,
  `testTheGrantHookIsBoundWhateverHooksAreListed`, `testAClassTheApplicationNamesInAuthorizationsConfigurationIsKept`,
  `testAnApplicationBindingWins`, `testWithTheSsoSwitchOffTheGrantHookIsLeftAlone`,
  `testWithTheSwitchOffNothingIsBound`, `testTheGrantHookIsMandatoryWhileDomainLinkingIsOn`,
  `testIamCheckRefusesTheCompositeWhileDomainLinkingIsOn`, `testAnIdentityOfAnotherKindIsPassedOverAndTheListedHooksRun`
- `tests/Integration/Authorization/GrantHookAdapterTest.php`, at the connection's own level on every engine, then at
  READ COMMITTED and REPEATABLE READ on MySQL and PostgreSQL,
  `testAGrantInATenantSuspendsTheLinkInAnotherTenantAndRevokesItsSessions`, `testAPlatformGrantSuspendsTheLink`,
  `testAGrantInTheLinksOwnTenantLeavesItAlone`, `testARefusalFromAListedHookRefusesTheGrant`,
  `testTheHooksTheApplicationListsRunOnceBeforeTheAdapter`, `testTheAdaptersRefusalAfterTheListedHooksRefusesTheGrant`,
  `testAGrantInsideTheApplicationsTransactionRollsBackWithIt`, `testASuspensionIsReportedForTheWideningsClient`; and
  `testTheAdapterIsTheBoundGrantHook`,
  `testAHookTheApplicationListsStillRunsBesideTheWidening`
- `tests/Integration/Authorization/GrantScopeAdapterTest.php` `testAPersonIsPlacedByTheirGrants`,
  `testTheJudgementReadsInsideTheCallersTransaction` (every level), `testAPersonIsPlacedByTheirPrincipalsGrants`,
  `testTheTreePlacesAGrantBelowTheTenantWithinIt`, `testATenantThatCannotBeResolvedThrows`,
  `testATenantAuthorizationCannotReadThrows`, `testATenantKeyedOtherwiseThanItsIdentifierThrows`,
  `testAnIdentityTheDirectoryCannotResolveIsIncomplete`, `testTheAdapterIsTheBoundGrantHalf`,
  `testATreeOfIntegerIdsPlacesAGrantInTheTenantWithinIt` (every level),
  `testAPrincipalAGlobalScopeHidesStillPlacesItsPerson`, `testAnIdentityWhosePrincipalsCannotBeListedIsUnknown`,
  `testAGrantBelowTheTenantInATenantOfAnotherTypeIsRefused`
- `tests/Integration/Authorization/TenantTreeAdapterTest.php` `testItAnswersTheApplicationsTree`,
  `testTheSubtreeSelectsEachTenantsTypeAndId` (every level), `testASubtreeIsNestedOnlyWhenItIsAQuery`,
  `testWithoutATreeARecordOnAnotherConnectionIsScopedByItsTenant` (every level), `testAskedWithNoTreeTheAdapterRefuses`,
  `testTheSubtreeSelectsEachIdAsText`, `testAReportedMoveReachesAuthorization` (every level, with
  `laravel-authorization`'s resolutions kept in a store, the move read as cached until it is reported),
  `testWithTheSwitchOffNothingIsReportedToAuthorization`, `testWithoutATreeNothingIsReportedToAuthorization`,
  `testATenantThatCannotBeNamedRefusesTheMove`, `testTheSubtreesTenantsAreListed`,
  `testATreeNestingTwoTenantTypesIsRefused`
- `tests/Integration/Authorization/TreeMoveWideningTest.php`
  `testAMoveOutFromUnderTheLinkedTenantSuspendsTheLinkInTheMovesTransaction`, `testAMoveThatRollsBackSuspendsNothing`
  (every level), `testWithTheSsoSwitchOffNobodyIsReported`, `testThePeopleGrantedAreReadFromEveryGrantTableEachOnce`,
  `testTheGrantTablesAreReadUnderTheirConfiguredNames`, `testAGrantTableNamedByWhatIsNoNameIsRefused`,
  `testAGranteeNamedByItsMorphAliasIsRead`,
  `testAMoveOfASubtreeHoldingAnotherTenantTypeIsRefused` (every level)
- `tests/Integration/EndToEnd/GroupGrantsThroughSsoTest.php`, at the connection's own level on every engine, then at
  READ COMMITTED and REPEATABLE READ on MySQL and PostgreSQL, `testAFirstSignInIsGrantedWhatItsGroupsMapTo`,
  `testARefusedMappingRollsTheProvisioningBack`, `testALaterSignInReSyncsTheGroups`,
  `testARefusedReSyncHandsOutNoCredential`, `testTheReSyncTakesTheIdentityGuardOnlyOnceTheRedemptionHasCommitted`;
  and `testASingleGroupIsMapped`, `testNoGroupsGrantNothing`,
  `testAnUnknownRoleRollsTheProvisioningBack`, `testWithNoMappingNothingIsGranted`,
  `testTheApplicationsOwnReSyncIsHandedPlainValues`, `testWithNoReSyncALaterSignInChangesNothing`
- `tests/Unit/Provisioning/GrantInstructionTest.php` `testARoleHoldsInTheTenantAloneUnlessItReachesBelow`,
  `testTheLongestNameIsAccepted`, `testAnInvalidNameIsRefused`; `tests/Unit/Provisioning/GroupSettingsTest.php`
  `testWithNothingConfiguredNothingIsMapped`, `testTheMapIsTheMappingWhileNothingElseIs`,
  `testABindingWinsOverTheClassNamed`, `testAMisconfigurationThrows`, `testTheShippedReSyncRefusesWithNoMapping`;
  `tests/Unit/Provisioning/ConfiguredGroupMappingTest.php` (this package's `GroupMappingTests`)
  `testEachRoleIsGrantedOnceInOrder`, `testAMisconfiguredMapThrows`, `testAnEmptyMapGrantsNothing`;
  `tests/Unit/Testing/FakeGroupMappingTest.php` (this package's `GroupMappingTests`)
  `testEachGroupMapsToWhatItWasToldOnce`, `testEveryQuestionIsRefusedOnceToldTo`, `testFakeBindsAFreshFakeAsTheMapping`,
  `testEveryCheckOfTheKitIsAPublicTest`, `testTheKitFailsAMappingThatAnswersDifferentlyEachTime`,
  `testTheKitFailsAGrantForUnmappedGroups`, `testTheKitFailsOtherGrantsThanTheGroupsGive`,
  `testTheKitFailsAnAnswerForADeclinedQuestion`
- `tests/Integration/Tenancy/TenantMembershipAdapterTest.php` `testAnAcceptedMembershipIsTheStanding` (at the
  connection's own level on every engine, then at READ COMMITTED and REPEATABLE READ on MySQL and PostgreSQL); and at
  the connection's own level alone, since each reads without a lock and commits nothing,
  `testNoAcceptedMembershipOfTheTenantIsNoStanding`, `testTheMembershipsAreAskedOnTheWriteConnection`,
  `testAnUnresolvedIdentityThrows`; `tests/Integration/Tenancy/MembershipRevocationRaceTest.php` (MySQL and
  PostgreSQL, both levels, memberships guarded as the contract asks)
  `testARevocationRacingAnActivationWaitsForItAndFindsItsSession`;
  `tests/Integration/Tenancy/LinkEligibilityAdapterTest.php` `testAnAcceptedMemberOfTheConnectionsTenantIsEligible`,
  `testNoAcceptedMembershipOfTheConnectionsTenantIsIneligible`;
  `tests/Integration/Tenancy/PrincipalScopeAdapterTest.php` `testTheVerdictComposesBothHalves`,
  `testWithTheAuthorizationSwitchOffTheGrantHalfLeavesNobodyWithin`,
  `testTheGrantHalfIsAskedOnlyWhenTheMembershipsLeaveItOpen`
- `tests/Integration/Tenancy/EnforcementInheritanceAdapterTest.php`, at the connection's own level on every engine, then
  at READ COMMITTED and REPEATABLE READ on MySQL and PostgreSQL, `testTheNearestTenantWithARuleEnforces`,
  `testTurningAnInnerRuleOffUnderAnEnforcingAncestorLeavesNoSessionOutOfCompliance`,
  `testAPasswordSignInBelowAnEnforcingAncestorIsRefused`, `testAnAncestorsRuleChangeRevokesThroughItsSubtree`; and at
  the connection's own level alone, `testSsosPolicyNamesTheEnforcingAncestor`,
  `testATenantHoldingOnlyTheLocksRowPassesTheQuestionUp`, `testABrokenTreeIsRefused`;
  `tests/Integration/Tenancy/InheritedEnforcementRaceTest.php` (MySQL and PostgreSQL, both levels)
  `testASessionThatEnteredAnInheritingTenantDuringTheChangeIsRevoked`;
  `tests/Integration/Tenancy/TreeMoveRaceTest.php` (MySQL and PostgreSQL, both levels, the tree held in the database
  and moved on another connection) `testATenantMovedUnderTheRootWhileItsRuleIsTurnedOnIsRevoked`;
  `tests/Integration/Sso/SessionRevocationAdapterTest.php`
  `testAnEnforcementChangeRevokesThroughTheEnforcingTenantsSubtree`, `testTheSecondPassJudgesTheSubtreeOnceItCommits`,
  `testAnUnresolvableTenantBelowTheEnforcingOneRollsTheChangeBack`
- `tests/Integration/Tenancy/TreeChangesTest.php` `testAMoveUnderAnEnforcingAncestorRevokesTheMovedSubtree`,
  `testARemovalIsReportedAsTheMoveOfEachChildOnceWritten`,
  `testASessionThatEntersTheSubtreeDuringTheMoveIsJudgedOnceItCommits`,
  `testATenantMovedInWhileTheRuleIsTurnedOnIsJudgedOnceTheChangeCommits`, `testAMoveThatRollsBackRevokesNothing`,
  `testWithNeitherEnforcementNorARequirementNothingIsJudged`, `testATenantRequirementAloneJudgesTheMovedSubtree`,
  `testWithoutATreeOnlyTheTenantIsJudged`, `testAnUnresolvableTenantOfTheSubtreeThrowsWithNothingJudged`,
  `testABrokenSubtreeIsRefused` (a descendant answered twice among them);
  `tests/Unit/Tenancy/SubtreePolicyChangesTest.php` `testACycleBelowTheTenantIsRefusedAtItsFirstRepeat`;
  `tests/Feature/IamManagerTest.php` `testTheTreeChangesAreReachedThroughTheirOwnService`
- `tests/Integration/EndToEnd/TenancyThroughSsoTest.php` `testAMemberOfTheConnectionsTenantIsLinked`,
  `testAnyoneElseIsRefusedAsIneligible`, `testADomainReservationLinksAMemberEndToEnd`,
  `testWithTheAuthorizationSwitchOffTheGrantHalfReservesNothing`, `testTheShippedGrantHalfLinksAMemberWithinTheTenant`,
  `testTheShippedGrantHalfLinksNobodyGrantedBeyondTheTenant`,
  `testAPersonNotWithinTheTenantSinceTheVerificationIsNotLinked`,
  `testALinkWhosePersonReachesBeyondTheTenantIsSuspended`
- `tests/Unit/Testing/FakeMembershipsTest.php` (this package's `MembershipsTests`)
  `testMembershipsAnswerThePersonsAcceptance`, `testMembershipsAnswerNoAcceptanceForAnAdministratorsMembership`,
  `testMembershipsAreNeverCompleteWhenUnreadable`, `testMembershipsAnswerEveryPrincipal`,
  `testTheKitFailsAnAdministratorsTimeAnsweredAsAnAcceptance`, `testTheKitFailsACompleteSetThatLeavesOutAPrincipal`;
  `tests/Unit/Testing/FakeTenantTreeTest.php` (this package's `TenantTreeTests`)
  `testTenantTreeAnswersAncestorsNearestFirst`, `testTenantTreeHasNoCycles`,
  `testTenantTreeDescendantsAgreeWithAncestors`, `testTenantTreeSubtreeIsTheTenantAndItsDescendants`,
  `testAPlacementThatWouldMakeACycleIsRefused`, `testTheKitFailsATreeWithACycle`,
  `testTheKitFailsATreeLeavingOutABranch`
- `tests/Performance/Tenancy/TenancyQueryBudgetTest.php` `testAMembershipJudgement`, `testAnInheritanceAnswer`,
  `testAReportedMoveOfASubtree`

## Change Triggers

Update this note when:

- `laravel-sso` changes `ResultUnlinked`, `ProvisioningGrant` or `ProvisioningHelper::link()` (its parameters, its
  order, its refusals, or whether the grant's claim survives a rollback, which decides whether the listener may retry);
- `laravel-sso` changes `ScopeWidening::widened()`'s parameters, its lock or its refusal outside a transaction;
- `laravel-authentication` gains an identity-creation contract of its own, or dispatches its unlinked result where a
  provisioner is expected to act on it;
- the application needs the provider's groups granted to the new membership's principal rather than to the identity
  (`createMembership()` would then answer the principal, and `GrantInstruction` name its grantee);
- Eloquent changes how it dispatches a model's `created` event, or `laravel-authentication` gains a signal of its own
  that an identity is new (the listener's insertion witness then follows it);
- `laravel-authorization` changes `GrantScopeQuery::forIdentity()`, its identity directory, its tenant tree contract,
  `treeChanged()`, its grant hook or `GrantWidening`, `GrantService::grantRole()` or `syncRoles()`, or names a tenant
  by its identifier (the translation between its `Reference` and the tree's ids then goes);
- `laravel-sso` changes `TenantMembership`, `LinkEligibility`, `PrincipalScope` or `EnforcementInheritance`, ships a
  contract kit for one of them (IAM-8.3), names the tenants that inherit a rule in its revocation scope, or locks the
  inheritance path in its admission and its changes (the inheritance reads may then lock too);
- `laravel-sso` starts revoking when a rule is turned off, or tells a rule turned off from one never stored otherwise
  than by its version (the inheritance adapter then reads the rule differently);
- Laravel stops registering the application's providers after the packages', or this package's booting callback moves
  (the tenancy rows are applied again there);
- the application's memberships or tree contract gains a method, or a member asks the tree for a tenant's type;
- `laravel-authentication`'s `tenantPolicyChanged()` stops skipping the sessions already recorded at the version it
  answers, or gains a way to judge the tenants a change reaches as one pass (a subtree's pass after the commit then
  lists and judges it otherwise);
- `laravel-sso` changes what protects `TenantMembership`'s answer (the membership guard may then go), or stops raising
  `links_version` for every link it makes, or its provisioning helper retries a serialisation failure itself (the
  listener's attempt may then keep the connection's level).
