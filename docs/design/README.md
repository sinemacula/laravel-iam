# Design Notes

These notes document the package's security and lifecycle contracts that are easy to miss if you only read the
quick-start material or skim the test suite.

Each note is intentionally short and follows the same structure:

- `Purpose`
- `Invariants`
- `Success Path`
- `Failure / Edge Cases`
- `Implementation Anchors`
- `Authoritative Tests`
- `Change Triggers`

The current note set is:

- `binding-precedence.md`: how the package binds its adapters over the members' seams once every provider has
  registered, only where a seam is unbound or its member says it still holds its own default, so the application's
  binding wins whatever order the providers register in.
- `storage-and-transactions.md`: the one storage connection every member is aligned to, how a change that spans
  members runs in one transaction on it, retried only when outermost, and work waiting on one connection's commit.
- `long-running-processes.md`: the combined worker reset that flushes every member's request state, the session that
  holds MFA's proofs among it, what it flushes before each Octane request and each queued job, why a job keeps its
  scoped instances and the application keeps its own instances, and how another long-lived process calls it.
- `authentication-and-mfa.md`: the twelve seams between `laravel-authentication` and `laravel-mfa` and the default each
  replaces; the `mfa` context namespace, filled from the contribution subject's session and its proofs; how an MFA
  application and sign-in are resolved to a guard and its current session, and refused when they cannot be; how proofs,
  channels, requirements, levels and changes are translated, `external_reauthentication` and `unclassified` among them;
  what each adapter answers and how it refuses; the evaluation a further proof is recorded with; and the lock order,
  identity state and factors before the session row, with what each isolation level does to a change that waited and why
  MFA's changes are never wrapped in another transaction.

- `codes-delivery-and-passkeys.md`: the code challenges `laravel-mfa` sends and checks through
  `laravel-authentication`'s factor codes under MFA's challenge counters, passkeys as MFA factors through
  `laravel-authentication`'s ceremonies and its mandatory passkey factor gate, and the event context, active tenant,
  subject type and application MFA reads from the validated session; how MFA's SMS and email senders forward its codes
  to the application's `OneTimeCodeSender`; and the locks each path takes.
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

- `install-and-check.md`: how `iam:install` publishes every member's configuration, language files and migrations, and
  this package's configuration, through `vendor:publish`; how it recognises a migration already published by its base
  name whatever its timestamp, so it is safe to run twice; the `laravel-authorization` table prefix it writes
  only into a configuration file it has just published, and what it reports as still owed; the
  members' scheduled work `Iam::schedule()` registers, and audit-log's own it never registers again; the PHP extensions
  the package declares; and how `iam:check` runs every member's check and this package's own: the storage connection and
  the identity models on it, every mandatory seam off its member's default under the mandate its row declares, the `mfa`
  and `sso` namespaces, the audit trail's settings, the configuration that crosses the members, SSO's side while SSO is
  in use and the schedule, every one reported under `iam:check` alone; what `laravel-authorization`'s glue adds, its
  prune and its resource tenant resolver's note among them; and the gaps in the members installation and the checks
  work around.

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

A note is added here with the code it describes.

These documents are secondary to the code and tests, not a replacement for them. If a note and a cited test disagree,
the test should be treated as authoritative until the mismatch is resolved.
