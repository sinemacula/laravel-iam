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
- `sso-redemption-and-revocation.md`: the seams between `laravel-authentication` and `laravel-sso`, SSO's own link
  store as its linker, and the handoff issuer left on SSO's default; how a `sign_in`, a
  `reauthenticate` and a `link` code are redeemed from plain values, the first two in one transaction on the storage
  connection retried whole and the last through SSO's standalone redemption; which refusals commit and which roll back;
  the records kept for one request and the one renewal a re-authentication writes; how each of SSO's revocation scopes
  ends exactly its sessions; how identity and tenant references are resolved; the provider's evidence through SSO's
  evidence policy and MFA's combination policy, freshness with SSO's maximum age, the application's external sign-in,
  link e-mail matching on verified identifiers, link confirmation from how the caller's session signed in, and the
  `sso` context namespace; SSO's lock order; and the gaps in the members the adapters work around.
- `tenant-authentication-policy.md`: `laravel-authentication`'s tenant authentication policy, answered from SSO's
  enforcement, its exemption gate and MFA's tenant requirement, and the version that reaches existing sessions.

- `provisioning-and-tenancy.md`: provisioning an unlinked SSO sign-in, group mapping, scope widening, and SSO's tenancy
  seams answered from the application's memberships and `laravel-authorization`'s tenant tree.

- `audit-mapping.md`: how `laravel-authentication`'s, MFA's, SSO's and `laravel-authorization`'s events are recorded in
  `laravel-audit-log`: the mappers, codes and definitions registered while the application boots, before audit-log
  freezes its registries; how each event is recorded from the event alone, under audit-log's own code where it means the
  same and a code of its member's prefix otherwise, a refusal by its flow and a concealed reason kept concealed, the
  actor the identity, no one or the caller, every reference through the morph map and every record correlated as one SSO
  sign-in, a challenge or a session; the whole record sequences of a password sign-in, an MFA step-up and an SSO
  sign-in; the one context contributor that fills a record's gaps from the caller a package guard already holds, never
  triggering authentication, and only on a record about that caller; the `jwt` and `api_key` guards excluded from
  audit-log's own capture, and its Gate capture off, so nothing is recorded twice, computed for the check to enforce,
  and audit-log's refusal of a code no definition registers read for them too; the operational
  events handed to the application's alerting; the trail read audit-log refuses inside a change that spans members;
  `laravel-authorization`'s decisions and changes, its access policy over the trail and the catalogue of the members'
  administrative permissions; and the gaps in the members the mapping works around.

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

- `authorization.md`: the seams that join `laravel-authorization` to the other members: the subject, the context and
  step-up, session caps, the grant hook, the audit access policy, and forgetting decisions when authentication changes.

A note is added here with the code it describes.

These documents are secondary to the code and tests, not a replacement for them. If a note and a cited test disagree,
the test should be treated as authoritative until the mismatch is resolved.
