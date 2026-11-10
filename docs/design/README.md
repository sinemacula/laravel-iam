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

- `binding-precedence.md`: how the package binds its adapters over the members' seams once, in `register()`, only where
  a seam is unbound or still the member's own default, so the application's binding wins whatever order the providers
  register in; how a member's default is told from the container's binding table; the lifetimes and the switches, read
  with each member's packaged configuration beneath the application's; and why the storage connection alone still
  waits for a `booting()` callback.
- `storage-and-transactions.md`: the one storage connection every member is aligned to and the boot refusal of a
  member on another, and how a change that spans members runs in one transaction on it, retried as a whole after a
  concurrency failure only when the package opened the outermost transaction, and rolled back to its savepoint inside
  a caller's.
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
  subject type and application MFA reads from the validated session; how both members' codes reach the application's
  email and SMS gateways as one neutral `CodeMessage`, routed by identifier type or factor channel; where each delivery
  runs, inside MFA's transaction or from `laravel-authentication`'s queued job once the code has committed, and so
  what a gateway that throws rolls back; and the locks each path takes.
- `sso-redemption-and-revocation.md`: the seams between `laravel-authentication` and `laravel-sso`, SSO's own link
  store as its linker and link storage, and the handoff issuer left on SSO's default; how a `sign_in`, a
  `reauthenticate` and a `link` code are redeemed from plain values, the first two in one transaction on the storage
  connection retried whole and the last through SSO's standalone redemption; which refusals commit and which roll back;
  the records kept for one request and the one renewal a re-authentication writes; how each of SSO's revocation scopes
  ends exactly its sessions; how identity and tenant references are resolved; the provider's evidence through SSO's
  evidence policy and MFA's combination policy, freshness with SSO's maximum age, the application's external sign-in,
  link e-mail matching on verified identifiers, link confirmation from how the caller's session signed in, and the
  `sso` context namespace; SSO's lock order; and the gaps in the members the adapters work around.
- `tenant-authentication-policy.md`: the application's one tenant MFA requirement and its rule, routed to MFA's
  tenant requirement and into `laravel-authentication`'s tenant authentication policy, which is answered from SSO's
  enforcement, SSO's exemption gate and that requirement together; the version that changes whenever any of them does;
  when the exemption gate is asked; the reads it makes and the lock it never takes; how an enforcement change and a
  changed requirement reach existing sessions; the testing kit and fake for the application's requirement; and the gaps
  in the members the adapters work around.

- `provisioning-and-tenancy.md`: the application's provisioner and the one listener of SSO's unlinked result that
  provisions a new identity, its membership and its link in one transaction attempted once, reading committed rows on
  PostgreSQL, in a fixed order after SSO's scope widening, with an identity that is not new refused and every write
  rolled back on a refusal or a failure; how a change that gives a person a principal reports it to SSO first, inside
  its own transaction; the application's memberships, guarded as they answer against a revocation racing a redemption,
  and tenant tree behind SSO's tenant membership, link eligibility, principal scope (whose grant half is
  `laravel-authorization`'s grant scope query, over the principals `laravel-authentication` lists) and enforcement
  inheritance, and behind `laravel-authorization`'s tree; how an enforcement change and a reported move of a tenant
  judge its whole subtree, a broken tree refused, and how the move reaches `laravel-authorization`; how a provider's
  groups map to grants at provisioning and, where the application opts in, at later sign-ins; the testing kits and
  fakes for the application's contracts; and the gaps in the members the adapters work around.

- `audit-mapping.md`: how `laravel-authentication`'s, MFA's, SSO's and `laravel-authorization`'s events are recorded in
  `laravel-audit-log`: the mappers, codes and definitions registered while the application boots, before audit-log
  freezes its registries; how each event is recorded from the event alone, under audit-log's own code where it means the
  same and a code of its member's prefix otherwise, a refusal by its flow and a concealed reason kept concealed, the
  actor the identity, no one or the caller, every reference through the morph map and every record correlated as one SSO
  sign-in, a challenge or a session; the whole record sequences of a password sign-in, an MFA step-up and an SSO
  sign-in; the one context contributor that fills a record's gaps from the caller a package guard already holds, never
  triggering authentication, and only on a record about that caller; the `jwt` and `api_key` guards excluded from
  audit-log's own capture, and its Gate capture off, so nothing is recorded twice, computed for installation to write
  and the check to enforce, and audit-log's refusal of a code no definition registers read for them too; the operational
  events handed to the application's alerting; the trail read audit-log refuses inside a change that spans members;
  `laravel-authorization`'s decisions and changes, its access policy over the trail and the catalogue of the members'
  administrative permissions; and the gaps in the members the mapping works around.

- `install-and-check.md`: how `iam:install` publishes every member's configuration, language files and migrations, and
  this package's configuration, in their working order, each where its provider publishes it; how it recognises a
  migration already published by its base name whatever its timestamp, tells it from an application's own of the same
  base name and fails the run where a migration's identity is in doubt, keeps every file already there and changes
  nothing it did not publish, so it is safe to run twice; the audit-log values and the prefixed `laravel-authorization`
  table names it writes only into a configuration file it has just published, and what it reports as still owed; the
  members' scheduled work `Iam::schedule()` registers, and audit-log's own it never registers again; the PHP extensions
  the package declares; and how `iam:check` runs every member's check and this package's own: the storage connection and
  the identity models on it, every mandatory seam off its member's default under the mandate its row declares, the `mfa`
  and `sso` namespaces, the audit trail's settings, the senders' gateways, the configuration that crosses the members,
  the platform and the schedule, with this package's checks of SSO's side registered with SSO's own, reported as
  `[iam]` and failing SSO's boot only while SSO is in use; what `laravel-authorization`'s glue adds, its prune and its
  resource tenant resolver's note among them; and the gaps in the members installation and the checks work around.

- `authorization.md`: the seams `laravel-authorization` joins the other members through: its subject resolver,
  answered from `Auth::caller()` and, for the model the Gate hands over, from the guard's resolved state, never the
  caller mid-admission; its authentication context, `laravel-authentication`'s with a fixed list of namespaces and the
  keys it declares to the key catalogue, those that say how the session was authenticated untestable; its requirement
  checker, answered by MFA's requirement check on the proofs of the subject's own session, each refusal undecidable;
  its insufficient-authentication exception, rendered as MFA's step-up from the request Laravel hands its handler; the
  session policy source, the scope registry and application access; how the binding rule replaces a member that binds
  its defaults unconditionally, and binds again what it replaced, never over a class the application names in that
  member's configuration; when the scope registry and application access are mandatory; the second part: the grant
  hook, answered by SSO's scope widening first inside the grant's own transaction, its lock order and its retries, the
  identity directory, the grant scope and the tree, the permission catalogue and the audit access policy, forgetting the
  request's last decision when the authentication it read changes, from the MFA adapters, and
  `laravel-authorization`'s connection, prune, check, request state and resource tenants; and the gaps in the members
  the adapters work around.

A note is added here with the code it describes.

These documents are secondary to the code and tests, not a replacement for them. If a note and a cited test disagree,
the test should be treated as authoritative until the mismatch is resolved.
