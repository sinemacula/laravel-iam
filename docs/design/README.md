# Design Notes

Short notes for maintainers on why each area works as it does. Each has its own sections, covering what the area does,
its decisions and invariants, and ends with a "Member gaps" list. Test lists and change triggers are left to the code.

- `binding-precedence.md`: how adapters are bound over the members' seams without replacing the application's
  bindings.
- `storage-and-transactions.md`: the one storage connection, cross-member transactions and their retries.
- `long-running-processes.md`: the worker reset under Octane, the queue and other long-lived processes.
- `authentication-and-mfa.md`: the seams between `laravel-authentication` and `laravel-mfa`, how an MFA sign-in maps
  to an authentication session, how proofs and requirements are translated, the `mfa` context namespace, the lock
  order, and the member gaps.

- `codes-delivery-and-passkeys.md`: MFA's code challenges through `laravel-authentication`'s factor codes, MFA's codes
  forwarded to the application's `OneTimeCodeSender`, passkeys as MFA factors, the context resolvers, their locks, and
  the member gaps.
- `sso-redemption-and-revocation.md`: the seams between `laravel-authentication` and `laravel-sso`, how SSO's handoff
  codes are redeemed and its revocation scopes end sessions, and how SSO's evidence, freshness and link judgements are
  answered.
- `tenant-authentication-policy.md`: the application's implementation of laravel-mfa's `TenantRequirement`, read
  into `laravel-authentication`'s tenant authentication policy, which is answered from SSO's enforcement, SSO's
  exemption gate and that requirement together; the version that changes whenever any of them does;
  when the exemption gate is asked; the reads it makes and the lock it never takes; how an enforcement change and a
  changed requirement reach existing sessions; the testing kit and fake for the application's requirement; and the gaps
  in the members the adapters work around.

- `provisioning-and-tenancy.md`: the application's provisioner and the one listener of SSO's unlinked result that
  provisions a new identity, its membership and its link in one transaction retried whole on a deadlock, in a fixed
  order after SSO's scope widening, with an identity that is not new refused and every write
  rolled back on a refusal or a failure; how a change that gives a person a principal reports it to SSO first, inside
  its own transaction; the application's memberships, guarded as they answer against a revocation racing a redemption,
  and `laravel-authorization`'s tenant tree behind SSO's tenant membership, link eligibility, principal scope (whose
  grant half is `laravel-authorization`'s grant scope query, over the principals `laravel-authentication` lists) and
  enforcement inheritance; how an enforcement change and a reported move of a tenant judge its whole subtree, and how
  the move reaches `laravel-authorization`; how a provider's
  groups map to grants at provisioning and, where the application opts in, at later sign-ins; the testing kits and
  fakes for the application's contracts; and the gaps in the members the adapters work around.

- `audit-mapping.md`: how the members' events are recorded in `laravel-audit-log`: registration, codes, actors and
  correlation, the guard caller reader, the capture exclusions, the audit access policy, and the member gaps.

- `install-and-check.md`: `iam:install`, `Iam::schedule()` and the checks `iam:check` runs.

- `authorization.md`: the seams `laravel-authorization` joins the other members through: its subject resolver,
  answered from `Auth::caller()` and, for the model the Gate hands over, from the guard's resolved state, never the
  caller mid-admission; its authentication context, `laravel-authentication`'s with a fixed list of namespaces, the
  keys it declares to the key catalogue with their types, and its assurance keys, which say how the session was
  authenticated and no condition may test; its requirement checker, answered by MFA's requirement check on the proofs
  of the subject's own session, each refusal undecidable; its insufficient-authentication exception, rendered as MFA's
  step-up from the request Laravel hands its handler; the session policy source, answered from the credential's scopes
  the subject resolver says on the subject, and failing closed for a credential named but not established, the scope
  registry and application access, which admits a machine on its
  grants as it admits a person; how the binding rule keeps a class the
  application names in `laravel-authorization`'s configuration, in whatever order the providers register; when the
  scope registry and application access are mandatory; the second part: the grant hook, answered by SSO's scope
  widening first inside the grant's own transaction, its lock order and its retries, the identity directory, the grant
  scope and the tree, the permission catalogue and the audit access policy, having `laravel-authorization` forget the
  request's decisions when the authentication they read changes, from the MFA adapters and the SSO reauthentication,
  and `laravel-authorization`'s connection, prune, check, request state and resource tenants; and the gaps in the
  members the adapters work around.

A note is added here with the code it describes. Where a note and the tests disagree, the tests win.
