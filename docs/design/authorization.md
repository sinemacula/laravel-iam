# Authorization

## Purpose

The package joins `laravel-authorization` to the other members: its subject, its authentication context and step-up,
the session caps on a credential's scopes, `laravel-authentication`'s scope registry and application access, the grant
hook that reports a widening to SSO, the audit access policy, and forgetting a request's decisions when its
authentication changes. The principal scope and group mapping are in `provisioning-and-tenancy.md`, the audit codes in
`audit-mapping.md`, and the binding rule in `binding-precedence.md`.

## Seams

Declared in `Authorization\AuthorizationSeams` and switched by `iam.adapters.authorization`:

| Member seam                              | Adapter                        | Default replaced             | Lifetime  | Mandatory while                  |
| ---------------------------------------- | ------------------------------ | ---------------------------- | --------- | -------------------------------- |
| AUTHZ `SubjectResolver`                  | `SubjectResolverAdapter`       | `AuthGuardSubjectResolver`   | scoped    | never                            |
| AUTHZ `AuthenticationContext`            | `AuthenticationContextAdapter` | `GuardAuthenticationContext` | transient | never                            |
| AUTHZ `AuthenticationRequirementChecker` | `RequirementCheckerAdapter`    | `RefusingRequirementChecker` | transient | never                            |
| AUTHZ `SessionPolicySource`              | `SessionPolicySourceAdapter`   | `NoSessionPolicy`            | transient | a guard accepts a machine method |
| AUTH `ScopeRegistry`                     | `ScopeRegistryAdapter`         | `AcceptAnyScope`             | transient | a guard accepts a machine method |
| AUTH `ApplicationAccess`                 | `ApplicationAccessAdapter`     | `AdmitAnyPrincipal`          | scoped    | `application_access` maps one    |
| AUTHZ `IdentityDirectory`                | `IdentityDirectoryAdapter`     | `GuardUserIdentityDirectory` | transient | never                            |
| AUTHZ `GrantHook`                        | `GrantHookAdapter`             | `GrantHooks`                 | transient | `sso.features.domain_linking`    |
| AUDIT `AuditAccessPolicy`                | `AuditAccessPolicyAdapter`     | `DenyAllPolicy`              | shared    | never                            |

- The requirement checker is bound only while `iam.adapters.mfa` is on too, and the grant hook only while
  `iam.adapters.sso` is.
- The machine methods are `api_key` and `client_credentials`, asked of the bound `ApplicationPolicy` when `iam:check`
  runs (`AccessMandates`), never while providers register.
- The grant half of SSO's principal scope (`Tenancy\Contracts\GrantScope`) is bound beside them by the service provider:
  `GrantScopeAdapter` while the switch is on, `UnknownGrantScope` while it is off.
- The tenant tree is the application's own binding of `laravel-authorization`'s `TenantTree`, and
  `laravel-authentication`'s tenant access stays on `OwnTenantOnly`.

## Decisions

- A row is bound only while the seam is unbound or `laravel-authorization` says it holds its default
  (`isPackageDefault()`), so a class the application names in `authorization.*` is kept in any provider order. Each row
  over `laravel-authorization`'s contracts is declared to `Diagnostics\Declarations` as `laravel-iam`'s, so
  `authorization:check` names it.
- The subject resolver is scoped because `laravel-authorization` keeps a resolved tenant only while the resolver that
  resolved it is still bound; a transient one would empty the resolution memo on every tenant-scoped read.
- `resolve()` builds the subject from `Auth::caller()`, with the credential's scopes on `Subject::$scopes`. `forUser()`
  never reads the caller, since application access asks it mid-admission: it reads the default guard only once it has
  resolved (`hasUser()`). The guard's own principal or identity is the caller; another principal is its own subject in
  its tenant with no session; any other model is its own subject and identity, in no tenant.
- A default guard that is not `laravel-authentication`'s is answered by `laravel-authorization`'s own resolver, with a
  `laravel-authentication` principal still mapped to its identity and tenant.
- The context's namespaces are fixed (`authentication`, `mfa`, `sso`) because `laravel-authorization` reads them as it
  boots, before this package's contributors register. `AuthenticationContextKeys` declares every key with its type on
  the key catalogue; a key already declared keeps its declaration.
- The assurance keys (`ASSURANCE_KEYS`) say how strongly or recently the session authenticated, so no policy may test
  them; a policy states an `authentication_requirement` instead. They are exact names, since
  `sso.provider_session_deadline` stays testable.
- The requirement checker judges only the subject's own session, found by key among its identity's sessions on the
  write connection, and only in the subject's tenant. It counts the first factor and every further proof since the
  oldest maximum age, `external_reauthentication` included, and asks MFA's `RequirementCheck`. An inactive identity
  meets nothing.
- `RequirementTranslator` maps `phishing_resistant` and `assurance_level` to MFA's parts. A level other than `aal1`,
  `aal2` or `aal3` throws, so the test is undecidable rather than judged at the nearest level.
- The step-up mapping is a render callback on Laravel's handler for the HTTP exception Laravel makes from
  `laravel-authorization`'s refusal. It maps only a refusal decided on the caller's own session: one about a subject the
  caller names was decided on no session, and no step-up could meet it, so it stays a 403.
- The session policy source answers in the contract's order and fails closed with `[]`: the scopes the subject says;
  `null` for a live session of the named guard owned by the subject's identity; the credential of a guard whose
  resolved caller is the subject; otherwise `null` for a person and `[]` for a machine.
- The scope registry asks `laravel-authorization`'s registry, the application's or the shipped
  `CatalogueScopeRegistry`, on every call, since the shipped one holds a scope map built once per request.
- Application access asks `laravel-authorization`'s `ApplicationAccess` about the principal in its own tenant, with no
  session caps, since a principal being admitted holds no session yet. An application the map leaves out is open to
  everyone.
- The grant hook runs inside the grant's transaction before `laravel-authorization` takes its locks, after the hooks
  `authorization.grant_hooks` lists. It calls `ScopeWidenings::widen()` once per distinct tenant of the widening
  (`null` for a platform grant), with the widening's client. A grantee that is not a `laravel-authentication` identity
  is passed over, since SSO never links one. Anything thrown refuses the grant and rolls the call back whole.
- A grant therefore takes SSO's locks first (the identity's guard, then its links), then `laravel-authorization`'s.
  Inside the application's transaction a conflict surfaces as `TransactionConflictException` and the whole transaction
  is retried; a trusted grant outside one is not retried, so the guide puts it inside `Iam::transaction()`.
- `TenantTranslator` takes `laravel-authorization`'s tenant key for `laravel-authentication`'s identifier only when the
  round trip resolves to the same tenant, and throws `UnresolvedReferenceException` otherwise. So `iam:check` refuses
  `ResolveNoTenant` while the authorization and SSO adapters are both on, or a tree is bound.
- The identity directory lists the identity's `principals()` on the write connection with global scopes set aside, so
  a soft-deleted principal's grants still count. A principal that owns no principals is complete and empty; a relation
  that is no Eloquent query, or an identity that cannot be resolved, is incomplete.
- The audit access policy turns the viewer's unconditional held permissions, tenant by tenant, into audit-log's
  `AccessScope`; `PermissionCatalogue` declares the administrative operations and the `audit-log.*` permissions, and
  `AdministrativeCheck` decides an operation where the subject acts, on the platform when it names no tenant.
- `DecisionCacheInvalidation::authenticationChanged()` has `laravel-authorization` forget the request's decisions
  (`forgetDecisionsFor()`) after an MFA factor change, a pending completion, a step-up or an SSO re-authentication. It
  forgets again if any transaction open on the storage connection rolls back, because Laravel 12 does not tell a
  committed savepoint of its enclosing transaction's rollback.
- `authorization.connection` is aligned with the storage connection like every member's, so a grant commits with a
  change that spans members and SSO's widening finds its transaction open.
- `authorization:prune` is scheduled daily by `Iam::schedule()` whatever the switch says, and `authorization:check`
  runs inside `iam:check`.
- No resource tenant resolver is bound, since which tenant owns a record is the application's rule; `iam:check` notes
  the default while memberships are bound.

## Invariants

- No adapter keeps anything between calls; the scoped ones are forgotten by the worker reset.
- A requirement is met only by proofs of the subject's own identity's session, in the subject's tenant.
- A machine is never uncapped for want of a credential.
- Every widening is reported to SSO in the grant's own transaction, so a refused grant leaves no suspension.
- A tenant crosses between `laravel-authorization` and the other members only by a round trip that resolves back.

## Member gaps

- `laravel-authorization` recognises a machine only by `AuthorizableMachine`, never `laravel-authentication`'s
  `MachineIdentity`, so the session policy source answers `[]` for a machine itself.
- `laravel-authorization` names a tenant by morph type and key (`Support\Reference`), never by
  `laravel-authentication`'s identifier, so `TenantTranslator` equates the two.
- `laravel-authorization`'s `ConflictRetries` does not recognise SSO's `LinkCandidatesChanged`, so the grant hook
  rethrows it as Laravel's `DeadlockException` with SQLSTATE `40001`.
- `laravel-mfa`'s `ConfirmedFactors` is `@internal`, so the step-up mapping filters `Mfa::factors()` for a confirmed
  factor.
- `laravel-authentication`, `laravel-mfa` and `laravel-sso` export no typed schema of their context keys, so
  `AuthenticationContextKeys` lists them.
