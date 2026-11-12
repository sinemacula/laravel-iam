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
