# SSO Redemption and Revocation

How the package joins `laravel-authentication` and `laravel-sso`: redeeming SSO's handoff codes, ending sessions when
SSO changes what they rest on, and answering SSO's judgements from `laravel-authentication` and `laravel-mfa`. The
tenant authentication policy is in `tenant-authentication-policy.md`; link eligibility, tenant membership, the tenant
tree and provisioning are in `provisioning-and-tenancy.md`; the binding rule is in `binding-precedence.md`; the storage
connection and retry helper are in `storage-and-transactions.md`.

## Seams

`Sso\SsoSeams` declares every binding, switched by `iam.adapters.sso` (lenient: only `false`, `0`, `off` or `no` turns
it off). Off, every member keeps its own default.

| Member seam                         | Bound to                          | Member default replaced       | Lifetime  |
| ----------------------------------- | --------------------------------- | ----------------------------- | --------- |
| SSO `ReauthenticationSessions`      | `ReauthenticationSessionsAdapter` | `NoReauthenticationSessions`  | transient |
| SSO `SessionRevocation` (mandatory) | `SessionRevocationAdapter`        | `NoSessionRevocation`         | transient |
| AUTH `ExternalIdentityLinks`        | `ExternalIdentityLinksAdapter`    | `NoExternalLinks`             | transient |
| SSO `Linker`                        | SSO's `Links\LinkStore`           | `NoLinks`                     | scoped    |
| AUTH `ExternalEvidencePolicy`       | `ExternalEvidencePolicyAdapter`   | `InsufficientEvidence`        | transient |
| SSO `Freshness`                     | `FreshnessAdapter`                | `RefusingFreshness`           | transient |
| SSO `ApplicationPolicy`             | `ApplicationPolicyAdapter`        | `ConfiguredApplicationPolicy` | transient |
| SSO `LinkEmailMatcher`              | `LinkEmailMatcherAdapter`         | `NoEmailMatches`              | transient |
| SSO `LinkConfirmation`              | `LinkConfirmationAdapter`         | `RefusingLinkConfirmation`    | transient |
| SSO `EvidencePolicy` (opt-in)       | SSO's `ConnectionEvidencePolicy`  | `InsufficientEvidence`        | scoped    |

- Session revocation is always mandatory: on SSO's default, a change SSO makes would leave the sessions it concerns
  standing. The links and the linker are mandatory while SSO is in use (`Features::isInUse()`); the re-authentication
  sessions while SSO's enforcement is on or the application binds MFA's tenant requirement. `iam:check` reads each.
- Links are SSO's: `laravel-authentication` stores none. SSO's `HandoffIssuer` is never rebound. `EvidencePolicy` is
  bound only while `iam.sso.evidence` is also on, read strictly since it widens what an assertion counts for.
- `SsoContextContributor` fills the `sso` context namespace. It is registered from a `booted()` callback, since a
  member may be registered from another provider's `boot()`, under the switch as it read when the seams were bound.

## Redemptions

The application calls `Iam::signIns()`, `Iam::reauthentications()` or `Iam::links()` with plain values: the
application, the connection, the code, the verifier and `laravel-authentication`'s `SignInContext` or `ClientContext`.
Nothing reads a request, the default guard or its current session. `Iam::callers()->of()` names a caller as SSO's
`Identities\Caller` for the application's own calls into SSO.

- The application SSO names is the `jwt` guard of the same name; anything else throws
  `UnresolvedReferenceException` before the code is touched.
- A sign-in and a re-authentication run in one transaction on the storage connection (`CrossMemberTransaction`),
  retried whole on a serialisation failure (SSO's `EnforcementPathChanged` among them), a deadlock or SSO's
  `LinkCandidatesChanged`, and only when outermost.
- A `link` goes through SSO's own `redeem()`, which retries in its own transaction, or runs as a savepoint of the
  caller's. It writes no session and is not retried here.
- SSO's refusal commits: the code is spent and `FlowFailed` follows the commit. `laravel-authentication`'s refusal rolls
  back through `ExternalSignInRefusedException` or `ExternalReauthenticationRefusedException`, leaving the code unspent;
  so does an admitted sign-in that links nobody (`UnlinkedSignInException`).
- The code and verifier reach the transaction wrapped in `SensitiveParameterValue`, so no trace holds them in the clear.
- The external result is built from the admitted redemption alone (`ExternalResults`). The link contract answers only
  from the redemption admitted in this request (`AdmittedRedemptions`), never by a second lookup. The records are
  scoped and forgotten by the worker reset and at the start and end of every attempt, so a retry never sees one rolled
  back.
- A re-authentication's renewal is recorded by the adapter (`RenewalRecorder`) and written once, by the redemption,
  through `reauthenticateExternally()`, which then has `laravel-authorization` forget the request's decisions. The
  recorder is open only while a redemption runs, so a `reauthenticate` code admitted through SSO's own `admit()` throws
  and rolls back with the code unspent.
- A sign-in re-syncs provider groups only after it commits: scope widening takes the identity's guard, which SSO locks
  before the connection the redemption holds.
- A concurrency failure the attempts do not outlast reaches the caller as a `DeadlockException` with SQLSTATE 40001.
- SSO's `renewAuthentication()` returns nothing, and a renewal needs the whole admitted result and must return the
  token, so the adapter records the renewal and the redemption writes it after `admit()`.

## Evidence

The provider's evidence passes two gates, and neither is the other.

- SSO's evidence contract accepts nothing by default; only what it accepted reaches `laravel-authentication`.
- MFA's combination policy judges that evidence as an `external_provider` first factor naming the connection. Its
  default classifies nothing a provider reports; an application trusts a provider by rebinding it.
- `accepts()` counts evidence only as exactly what SSO accepted in this request's redemption, for the identity it
  linked. `meets()` also requires a tenant's requirement to come from a connection the tenant trusts: its own, or one
  its enforcement names (`ConnectionTrust`). A requirement that asks for nothing is never met.
- Elsewhere the proof translator names the connection to MFA only for evidence SSO accepted from a connection the
  session's tenant trusts (`Mfa\Translation\ProviderTrust`), and never to `laravel-authentication`'s requirement check.
- Tenant trust is judged here, in the SSO-aware evidence policy, since `laravel-authentication` knows nothing of who
  owns a connection.

## SSO's judgements

- Freshness asks `laravel-authentication`'s freshness policy with SSO's maximum age as the requirement, on the caller's
  own session only. Inside SSO's transaction it reads current, locking the session row last, since SSO asks only once
  its own locks are held; outside one it reads plainly.
- Link confirmation is `independent` only for a session whose first factor was a password, passkey or recovery, with no
  provider re-authentication and no verified-domain link provenance. It reads under the session's row lock inside
  SSO's transaction, and is `dependent` outside one.
- The application policy allows an external sign-in exactly when `laravel-authentication` lets the guard start sessions
  by `external_provider`; SSO's own `external_sign_in` setting is not read.
- Link email matching uses `laravel-authentication`'s `email` normaliser and counts an identity only when that exact
  address is verified: one is `exactly one`, more is `ambiguous`. It takes no lock and relies on a verified email being
  unique.
- The `sso` namespace projects the provider context the sign-in stored through SSO's
  `AuthenticationContext::fromStored()`: no keys without one, all twelve otherwise. Failures propagate.

## Revocation

`SessionRevocationAdapter` maps each of SSO's scopes to the `laravel-authentication` helper that ends exactly those
sessions, on every guard, as a savepoint of SSO's transaction:

| Scope kind (reason)                    | Helper                          | Switch                     |
| -------------------------------------- | ------------------------------- | -------------------------- |
| `tenant` (`enforcement_changed`)       | `tenantPolicyChanged()`, twice  | none                       |
| `connection` (`connection_disabled`)   | `connectionDisabled()`          | `laravel-authentication`'s |
| `connection` (`connection_deleted`)    | `connectionDeleted()`           | `laravel-authentication`'s |
| `identity_connection` (`link_removed`) | `linkRemovedByReference()`      | `laravel-authentication`'s |
| `identity_link` (`scope_widened`)      | `linkScopeWidenedByReference()` | none, not `link_removed`   |

- An enforcement change judges the enforcing tenant and every tenant below it in the application's tree
  (`Tenancy\SubtreePolicyChanges`), inside SSO's transaction and again after it commits, so a session that entered the
  tenant meanwhile is caught.
- A removed link or widened scope names the identity by SSO's reference and reads no identity, so the sessions of one
  soft-deleted, outside a global scope or no longer stored end too.
- An unresolved tenant, an identity reference whose type is not an Eloquent identity model's morph class or whose id
  lacks its key's shape (`InvalidArgumentException`), an incomplete scope or an unknown reason throws, rolling SSO's
  change back.

## References and locks

- `IdentityReferences` resolves SSO's reference through `laravel-authentication`'s `IdentityReferences::resolve()`, on
  the write connection, and only when the identity's morph class and key match the reference byte for byte.
- Every adapter follows SSO's lock order, with the session's row always last. Nothing locks after
  `reauthenticateExternally()`, and nothing locks a session's row and then calls into SSO.

## Contract kits

Each adapter's test runs SSO's kit for its seam: `FreshnessContract`, `LinkConfirmationContract`,
`LinkEmailMatcherContract`, `ReauthenticationSessionsContract`, `SessionRevocationContract` and
`EnforcementInheritanceContract`. The revocation kit runs over SSO's stored rule, the tenant policy adapter, the
application's exemptions and its tree.
