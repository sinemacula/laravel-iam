# Design Notes

Short notes for maintainers on why each area works as it does. Each has its own sections, covering what the area does,
its decisions and invariants, and ends with a "Member gaps" list. Test lists and change triggers are left to the code.

- `binding-precedence.md`: how adapters are bound over the members' seams without replacing the application's
  bindings.
- `storage-and-transactions.md`: the one storage connection, cross-member transactions and their retries.
- `long-running-processes.md`: the worker reset under Octane, the queue and other long-lived processes.
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
- `tenant-authentication-policy.md`: `laravel-authentication`'s tenant authentication policy, answered from SSO's
  enforcement, its exemption gate and MFA's tenant requirement, and the version that reaches existing sessions.

- `provisioning-and-tenancy.md`: provisioning an unlinked SSO sign-in, group mapping, scope widening, and SSO's tenancy
  seams answered from the application's memberships and `laravel-authorization`'s tenant tree.

- `audit-mapping.md`: how the members' events are recorded in `laravel-audit-log`: registration, codes, actors and
  correlation, the guard caller reader, the capture exclusions, the audit access policy, and the member gaps.

- `install-and-check.md`: `iam:install`, `Iam::schedule()` and the checks `iam:check` runs.

- `authorization.md`: the seams that join `laravel-authorization` to the other members: the subject, the context and
  step-up, session caps, the grant hook, the audit access policy, and forgetting decisions when authentication changes.

A note is added here with the code it describes. Where a note and the tests disagree, the tests win.
