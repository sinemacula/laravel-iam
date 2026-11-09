# Bindings

This package joins the members by binding each member's contracts (its seams) to an adapter that answers them from
another member. This guide lists every binding it makes: what each seam is bound to, which member default the adapter
replaces, whether `iam:check` holds the seam mandatory, how to replace it, and whether replacing it can make the suite
insecure. What each contract means on its own side is in that member's guide; the links are at the end of each section.

Classes are named relative to `SineMacula\Laravel\`: `Mfa\Contracts\StepUp` is
`SineMacula\Laravel\Mfa\Contracts\StepUp`, and `Iam\Mfa\StepUpAdapter` is this package's
`SineMacula\Laravel\Iam\Mfa\StepUpAdapter`. Every adapter is internal to this package: bind the contract, never extend
or call an adapter.

- [The binding rule](#the-binding-rule)
- [Replacing a binding](#replacing-a-binding)
- [Authentication and MFA](#authentication-and-mfa)
- [Passkeys](#passkeys)
- [MFA's context](#mfas-context)
- [Code delivery](#code-delivery)
- [Authentication and SSO](#authentication-and-sso)
- [Tenancy](#tenancy)
- [Other bindings](#other-bindings)
- [Mandatory seams still to come](#mandatory-seams-still-to-come)

## The binding rule

- A seam is bound to its adapter only while it is unbound or still bound to its member's own default. Your
  application's binding always wins: one made before this package registers is kept, and one made after it, in your
  own provider's `register()` or `boot()`, replaces the adapter as any later binding does. The order the service
  providers register in changes nothing.
- The rule runs in `register()`. Two switches turn whole groups of bindings off: `iam.adapters.mfa` (authentication
  and MFA, passkeys, MFA's context) and `iam.adapters.sso` (authentication and SSO, tenancy). Code delivery follows
  `iam.delivery`. See [Configuration](configuration.md).
- Adapters are transient: each reads what it needs afresh on every call. An adapter that keeps request state is bound
  scoped, under a key of this package's own (`iam.scoped:` followed by the seam), with the seam itself bound to a
  closure that resolves that key. Laravel's queue worker and Octane forget scoped instances between jobs and requests,
  and `Iam::resetWorkerState()` forgets them for any other long-lived process (see [Operations](operations.md)).
- A seam marked mandatory below is one `iam:check` fails on while it is unbound, still on its member's permissive or
  inert default, or bound through a closure it cannot read. `Always` means under every configuration; `While ...`
  names the configuration that makes it so. See [Checks](checks.md#seams).

## Replacing a binding

Bind the contract in your own service provider, by class name or as an instance:

```php
use App\Auth\AuditedStepUp;
use SineMacula\Laravel\Mfa\Contracts\StepUp;

public function register(): void
{
    $this->app->bind(StepUp::class, AuditedStepUp::class);
}
```

A binding in place before this package registers is kept, and `iam:check` notes it (`note: ... keeps the
application's binding`); one made later replaces the adapter silently. Either way the check reads the live binding of
every mandatory seam. On a mandatory seam, bind a class name or an instance, never a closure: the check cannot tell
what a closure returns, so it refuses it.

Whatever you bind in an adapter's place takes on the adapter's duties, which the members' guides describe and this
package's adapters keep:

- Take plain values and nothing else. Read no request, cookie or header, and never ask `Auth::user()`, the guard's
  current session or the default guard when the member hands you the identity, the session or the application.
- Refuse only by throwing. An unresolved identity, session or tenant throws inside the member's transaction, so the
  change it was making rolls back.
- Keep no request state in a property. State for one request belongs in a scoped binding, which Octane and the queue
  worker forget at each boundary; `Iam::resetWorkerState()` forgets only the suite's own, so a loop of your own also
  calls the container's `forgetScopedInstances()` (see
  [Operations](operations.md#workers-and-octane)).
- Take the locks the member's guide names, in the order it names. SSO's adapters follow SSO's lock order
  ([laravel-sso: lock order][sso-lock-order]).

Turning `iam.adapters.mfa` or `iam.adapters.sso` off leaves every seam of its groups on the members' defaults, most of
which refuse or do nothing. Bind every seam of those groups yourself; `iam:check` still holds you to the mandatory
ones.

## Authentication and MFA

Bound while `iam.adapters.mfa` is on. MFA's challenge gateway is bound only while `laravel-authentication`'s one-time
code sender is bound too (see [Code delivery](#code-delivery)); otherwise MFA keeps its own challenges. Every adapter
here is transient. The joins are described in [Authentication and MFA](authentication-and-mfa.md).

| Contract                                          | Bound to                                | Replaces                                              | Mandatory | Replacing it                                                                                                                                                                                             |
|---------------------------------------------------|-----------------------------------------|-------------------------------------------------------|-----------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `Authentication\Contracts\AdditionalFactorPolicy` | `Iam\Mfa\AdditionalFactorPolicyAdapter` | `Authentication\Factors\NeverRequireAdditionalFactor` | No        | Sign-in asks MFA whether a further factor is due. A policy that answers less than MFA's requirement lets a sign-in activate without the factor MFA requires.                                             |
| `Authentication\Contracts\RequirementCheck`       | `Iam\Mfa\RequirementCheckAdapter`       | `Authentication\Requirements\MeetNoRequirement`       | No        | One answer serves sign-in, a tenant's policy, step-up and authorization. A check of your own splits them: a requirement MFA leaves unmet can be met for `laravel-authentication`.                        |
| `Mfa\Contracts\PendingSessionResolver`            | `Iam\Mfa\PendingSessionResolverAdapter` | `Mfa\Context\NoPendingSessionResolver`                | No        | Its `fromRequest()` reads the pending credential from the request body only. A resolver that reads it from the query string or a header widens where the credential can leak.                            |
| `Mfa\Contracts\PendingCompletion`                 | `Iam\Mfa\PendingCompletionAdapter`      | `Mfa\Proofs\ProofStoreCompletion`                     | No        | Activates the pending session as the last write of MFA's transaction. A completion that writes earlier, or outside it, can activate a session whose verification then rolls back.                        |
| `Mfa\Contracts\StepUp`                            | `Iam\Mfa\StepUpAdapter`                 | `Mfa\Proofs\ProofStoreCompletion`                     | No        | Steps up the session the proof is bound to. A step-up that raises the guard's current session instead can raise another session than the one verified.                                                   |
| `Mfa\Contracts\Reauthenticator`                   | `Iam\Mfa\ReauthenticatorAdapter`        | `Mfa\Seams\RefusingReauthenticator`                   | No        | Finds the reauthentication `laravel-authentication` recorded on the session. One that answers a proof the session does not hold lets a factor change go ahead without a fresh first factor.              |
| `Mfa\Contracts\FreshnessGate`                     | `Iam\Mfa\FreshnessGateAdapter`          | `Mfa\Requirements\ConfiguredFreshnessGate`            | No        | Asks `laravel-authentication`'s freshness policy about the caller's own session. A gate that answers fresh more readily lets MFA's sensitive operations run on a stale session.                          |
| `Mfa\Contracts\FactorChangeGate`                  | `Iam\Mfa\FactorChangeGateAdapter`       | `Mfa\Requirements\ConfiguredFactorChangeGate`         | No        | Locks the session and judges its freshness inside MFA's transaction, after MFA's locks. A gate without the lock can let a change commit after the session was revoked.                                   |
| `Mfa\Contracts\SessionRevoker`                    | `Iam\Mfa\SessionRevokerAdapter`         | `Mfa\Proofs\GenerationSessionRevoker`                 | Always    | Ends the identity's other sessions inside MFA's transaction when a factor is removed or reset. Left on MFA's default, every other session of the identity stays standing.                                |
| `Mfa\Contracts\SessionTransition`                 | `Iam\Mfa\SessionTransitionAdapter`      | `Mfa\Http\MiddlewareSessionTransition`                | No        | Returns a session that stops meeting its requirement after a factor change to pending. One that skips it leaves the session active.                                                                      |
| `Mfa\Contracts\ProofStore`                        | `Iam\Mfa\ProofStoreAdapter`             | `Mfa\Proofs\ProofBindings`                            | No        | Serves MFA the proofs `laravel-authentication` recorded, each counted only while it names one of the identity's factors. A store of your own lets MFA count evidence `laravel-authentication` never saw. |
| `Mfa\Contracts\FirstFactorResolver`               | `Iam\Mfa\FirstFactorResolverAdapter`    | `Mfa\Applications\DeclaredFirstFactorResolver`        | No        | Answers the first factor the session recorded, and none it cannot express. A resolver that declares one lets MFA trust a first factor it was never given.                                                |
| `Mfa\Contracts\ChallengeGateway`                  | `Iam\Mfa\ChallengeGatewayAdapter`       | `Mfa\Codes\PackageChallengeGateway`                   | No        | Sends MFA's `email` and `sms` codes through `laravel-authentication`'s factor codes, and every other through MFA's own gateway. A gateway of your own must count attempts as MFA does.                   |
| `Authentication\Contracts\FactorCodeCounters`     | `Iam\Mfa\FactorCodeCountersAdapter`     | `Authentication\Codes\RefuseFactorCodes`              | No        | Counts every factor code attempt against MFA's challenge counters. Counters that do not count let a code be guessed past MFA's limits.                                                                   |
| `Mfa\Contracts\TenantRequirement`                 | `Iam\Mfa\TenantRequirementAdapter`      | `Mfa\Requirements\NoTenantRequirement`                | No        | Answers from your tenant MFA requirement, the answer the tenant authentication policy is given too. A requirement of your own can make the two members disagree about a tenant.                          |

Your application's own step-up, if it has one, must name one of MFA's factors: the proof store counts no proof that
names none. The members' sides: [laravel-mfa: extending][mfa-extending] and
[laravel-authentication: extending][authentication-extending].

## Passkeys

Bound while `iam.adapters.mfa` is on. MFA's passkey gateway is bound only while some MFA application offers the
`passkey` type (`mfa.applications.*.types`). Both are transient.

| Contract                                     | Bound to                           | Replaces                                   | Mandatory | Replacing it                                                                                                                                                                          |
|----------------------------------------------|------------------------------------|--------------------------------------------|-----------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `Mfa\Contracts\PasskeyGateway`               | `Iam\Mfa\PasskeyGatewayAdapter`    | `Mfa\Passkeys\UnavailablePasskeyGateway`   | No        | Runs passkey ceremonies through `laravel-authentication`'s passkeys, bound to the identity, sign-in and purpose. A gateway of your own must keep that binding.                        |
| `Authentication\Contracts\PasskeyFactorGate` | `Iam\Mfa\PasskeyFactorGateAdapter` | `Authentication\Passkeys\NoPasskeyFactors` | Always    | Calls MFA's passkey change gate inside the passkey transaction. Left on the default, removing a passkey leaves its factor and association standing, even after the type is withdrawn. |

## MFA's context

Bound while `iam.adapters.mfa` is on; every adapter is transient. MFA asks these who its caller is.

| Contract                             | Bound to                              | Replaces                                  | Mandatory                                                 | Replacing it                                                                                                                                                                                                        |
|--------------------------------------|---------------------------------------|-------------------------------------------|-----------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `Mfa\Contracts\EventContextResolver` | `Iam\Mfa\EventContextResolverAdapter` | `Mfa\Context\DefaultEventContextResolver` | No                                                        | Fills MFA's event context with scalars, never a model, a secret or a full destination. A resolver that adds them puts them in MFA's events and the audit trail.                                                     |
| `Mfa\Contracts\ActiveTenantResolver` | `Iam\Mfa\ActiveTenantResolverAdapter` | `Mfa\Requirements\NoActiveTenant`         | While SSO's enforcement or a tenant MFA requirement is on | Reads the tenant the validated session records, never one the request claims. Left on the default, no tenant's requirement reaches MFA; one that reads the request lets a caller choose the tenant it is judged by. |
| `Mfa\Contracts\SubjectTypeResolver`  | `Iam\Mfa\SubjectTypeResolverAdapter`  | `Mfa\Context\IdentityContractSubjectType` | No                                                        | Treats every `Authentication\Contracts\MachineIdentity` as a machine. A resolver that takes a machine for a person lets MFA's operations run for an API client.                                                     |
| `Mfa\Contracts\ActiveStateResolver`  | `Iam\Mfa\ActiveStateResolverAdapter`  | `Mfa\Context\IdentityContractActiveState` | No                                                        | Reads `laravel-authentication`'s active state on the write connection. A resolver that reads a replica can serve an identity just deactivated.                                                                      |
| `Mfa\Contracts\ApplicationResolver`  | `Iam\Mfa\ApplicationResolverAdapter`  | None: MFA binds no default                | No                                                        | Names MFA's application after the guard that serves the request. A resolver that names another lets MFA judge a caller under another application than its session's.                                                |

## Code delivery

Each row is bound only while the gateway it delivers through is available: the one-time code sender while every
identifier type `iam.delivery.types` routes reaches a named or bound gateway, and each MFA sender while its gateway is
named or bound. A gateway bound after this package registers comes too late to bind these: name it in
`iam.delivery.email` or `iam.delivery.sms` instead. All are transient and none is mandatory; your gateways write the
messages ([Configuration](configuration.md#delivery)).

| Contract                                     | Bound to                                | Replaces                                        | Mandatory | Replacing it                                                                                                                                                 |
|----------------------------------------------|-----------------------------------------|-------------------------------------------------|-----------|--------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `Authentication\Contracts\OneTimeCodeSender` | `Iam\Delivery\OneTimeCodeSenderAdapter` | None: `laravel-authentication` binds no default | No        | Sends `laravel-authentication`'s codes, and MFA's through it, through your gateways. A sender of your own must deliver only to the destination it is handed. |
| `Mfa\Contracts\SmsSender`                    | `Iam\Delivery\SmsSenderAdapter`         | `Mfa\Codes\NullSmsSender`                       | No        | Sends MFA's SMS codes through your SMS gateway. A sender of your own must deliver only to the destination it is handed.                                      |
| `Mfa\Contracts\EmailSender`                  | `Iam\Delivery\EmailSenderAdapter`       | `Mfa\Codes\NullEmailSender`                     | No        | Sends MFA's email codes through your email gateway. A sender of your own must deliver only to the destination it is handed.                                  |

## Authentication and SSO

Bound while `iam.adapters.sso` is on. SSO is in use while one of its protocols is on (`sso.features.saml2` or
`sso.features.oidc`). The joins, and the order every adapter takes its locks in, are described in
[Authentication and SSO](authentication-and-sso.md) and [laravel-sso: integrating with laravel-iam][sso-integrating].

| Contract                                          | Bound to                                        | Replaces                                                                   | Mandatory                                                 | Replacing it                                                                                                                                                                                                  |
|---------------------------------------------------|-------------------------------------------------|----------------------------------------------------------------------------|-----------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `Sso\Contracts\ReauthenticationSessions`          | `Iam\Sso\ReauthenticationSessionsAdapter`       | `Sso\Flows\NoReauthenticationSessions`                                     | While SSO's enforcement or a tenant MFA requirement is on | Renews a session through the link that established it. Left on the default, nobody held to a tenant's rule can renew a session through SSO.                                                                   |
| `Sso\Contracts\SessionRevocation`                 | `Iam\Sso\SessionRevocationAdapter`              | `Sso\Revocation\NoSessionRevocation`                                       | Always                                                    | Ends the sessions an SSO change concerns. Left on the default, an enforcement change, a disabled or deleted connection, a removed link or a widened scope leaves every session it concerns standing.          |
| `Authentication\Contracts\ExternalIdentityLinks`  | `Iam\Sso\ExternalIdentityLinksAdapter`          | `Authentication\External\NoExternalLinks`                                  | While SSO is in use                                       | Answers only the redemption SSO admitted for the request. Links of your own that look a result up themselves can sign in a result SSO never admitted; left on the default, no SSO sign-in finds its identity. |
| `Sso\Contracts\Linker`                            | `Sso\Links\LinkStore`, scoped                   | `Sso\Links\NoLinks`                                                        | While SSO is in use                                       | SSO's own link store, bound because SSO binds a linker that links nothing. Left on the default, no link can be made or found.                                                                                 |
| `Sso\Contracts\LinkStorage`                       | `Iam\Sso\BoundLinkStorage`, scoped              | None: SSO binds no default; an application's `Sso\Links\LinkStore` is kept | While SSO is in use                                       | Answers from the bound linker, so storage and linker never disagree. Storage of your own can read links other than those SSO resolves.                                                                        |
| `Authentication\Contracts\ExternalEvidencePolicy` | `Iam\Sso\ExternalEvidencePolicyAdapter`         | `Authentication\External\InsufficientEvidence`                             | No                                                        | Accepts only what SSO's evidence contract accepted, with MFA's combination policy as the second gate. A policy that reads a provider's `amr` itself widens what an SSO session satisfies.                     |
| `Sso\Contracts\Freshness`                         | `Iam\Sso\FreshnessAdapter`                      | `Sso\Freshness\RefusingFreshness`                                          | No                                                        | Answers from `laravel-authentication`'s freshness policy with SSO's maximum age. A contract that answers fresh more readily lets SSO's administration run on a stale session.                                 |
| `Sso\Contracts\ApplicationPolicy`                 | `Iam\Sso\ApplicationPolicyAdapter`              | `Sso\Applications\ConfiguredApplicationPolicy`                             | No                                                        | Lets SSO serve an application exactly while its guard allows `external_provider`. A policy of your own can start flows `laravel-authentication` refuses at redemption.                                        |
| `Sso\Contracts\LinkEmailMatcher`                  | `Iam\Sso\LinkEmailMatcherAdapter`               | `Sso\Linking\NoEmailMatches`                                               | No                                                        | Matches the email SSO asserts against verified addresses, through `laravel-authentication`'s email normaliser. A looser matcher can link a person to someone else's account.                                  |
| `Sso\Contracts\LinkConfirmation`                  | `Iam\Sso\LinkConfirmationAdapter`               | `Sso\Linking\RefusingLinkConfirmation`                                     | No                                                        | Confirms a verified domain link only from the caller's own password, passkey or recovery session. One trusting a session a provider established lets the domain's provider confirm for the person.            |
| `Sso\Contracts\EvidencePolicy`                    | `Sso\Evidence\ConnectionEvidencePolicy`, scoped | `Sso\Evidence\InsufficientEvidence`                                        | No                                                        | Bound only while `iam.sso.evidence` is `true`, and widens what a session can satisfy. Read [MFA and SSO](mfa-and-sso.md) before you turn it on or bind your own.                                              |

SSO's handoff issuer is never bound: under this package an unlinked result is provisioned or refused, never handed
off ([Provisioning and tenancy](provisioning-and-tenancy.md)).

## Tenancy

Bound while `iam.adapters.sso` is on. With it off, bind `laravel-authentication`'s tenant authentication policy
yourself. The membership rows are bound while memberships are named in `iam.tenancy.memberships` or bound, and the
inheritance row while a tree is named in `iam.tenancy.tree` or bound. These rows are applied a second time from the
booting phase, so memberships or a tree you bind in your own provider's `register()` still get them. All are
transient. SSO's own defaults for the membership rows refuse, so leaving them unbound is never open. See
[Provisioning and tenancy](provisioning-and-tenancy.md).

| Contract                                              | Bound to                                        | Replaces                                         | Mandatory                                                         | Replacing it                                                                                                                                                                         |
|-------------------------------------------------------|-------------------------------------------------|--------------------------------------------------|-------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `Authentication\Contracts\TenantAuthenticationPolicy` | `Iam\Tenancy\TenantAuthenticationPolicyAdapter` | `Authentication\Tenancy\RequireNothingOfTenants` | While SSO's enforcement or a tenant MFA requirement is on         | Answers SSO's enforcement, its exemptions and your tenant MFA requirement together. Left on the default, no tenant's enforcement or requirement reaches a session.                   |
| `Sso\Contracts\TenantMembership`                      | `Iam\Tenancy\TenantMembershipAdapter`           | `Sso\Linking\NoTenantMembership`                 | No                                                                | Counts only a membership the person accepted. A contract that counts an invitation lets a domain link people who never joined the tenant.                                            |
| `Sso\Contracts\LinkEligibility`                       | `Iam\Tenancy\LinkEligibilityAdapter`            | `Sso\Linking\RefusingLinkEligibility`            | No                                                                | Lets a person link only as an accepted member of the connection's tenant. A looser contract makes people reachable through a provider of a tenant they do not belong to.             |
| `Sso\Contracts\PrincipalScope`                        | `Iam\Tenancy\PrincipalScopeAdapter`             | `Sso\Linking\RefusingPrincipalScope`             | No                                                                | Answers `unknown` unless memberships and grants both say otherwise. A contract that answers `within_tenant` too readily lets a tenant's provider reach people with access beyond it. |
| `Sso\Contracts\EnforcementInheritance`                | `Iam\Tenancy\EnforcementInheritanceAdapter`     | `Sso\Enforcement\OwnTenantInheritance`           | While SSO's enforcement is on and a tenant tree is named or bound | Finds the nearest tenant up the tree with a rule. Left on the default, a parent's SSO-only rule never reaches its descendants.                                                       |

## Other bindings

The package also binds services of its own, which are not members' seams. Most are not yours to replace: replacing one
of those breaks what the row says it holds. Four keep a binding or registration of yours (the grant scope, the `mfa`
and `sso` context contributors and SSO's `iam` check), and audit-log's context contributor sits beside any of yours;
each of those rows says what replacing it, or adding your own, risks.

| Binding                                                                         | Bound to                        | Lifetime                                                 | Notes                                                                                                                                                                                 | Replacing it                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
|---------------------------------------------------------------------------------|---------------------------------|----------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `iam`, and `Iam\IamManager` as its alias                                        | `Iam\IamManager`                | Shared                                                   | Behind the `Iam` facade.                                                                                                                                                              | Do not replace it.                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `Iam\Tenancy\Contracts\GrantScope`                                              | `Iam\Tenancy\UnknownGrantScope` | Shared, bound only if unbound                            | The grant half of SSO's principal scope, `unknown` until `laravel-authorization` answers it.                                                                                          | Yours is kept, but leave it on `Iam\Tenancy\UnknownGrantScope` until `laravel-authorization`'s grant scope query is bound. An implementation that answers `within_tenant` for a person whose grants (platform-wide ones included) reach beyond the tenant lets that tenant's verified domain link the person, so its provider can sign in as them.                                                                                                               |
| `Iam\Sso\AdmittedRedemptions`, `Iam\Sso\RenewalRecorder`, `Iam\Sso\LinkCallers` | Themselves                      | Scoped, under `iam.scoped:`                              | One request's or job's record of an SSO redemption.                                                                                                                                   | Do not replace them.                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `Iam\Audit\DeferredRefusals`                                                    | Itself                          | Scoped, under `iam.scoped:`                              | The refusals held until the outermost transaction on audit-log's connection ends.                                                                                                     | Do not replace it.                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `Iam\Transactions\OutermostCommits`, `Iam\Transactions\CommittedWork`           | Themselves                      | Scoped, under `iam.scoped:`                              | One request's or job's work waiting for its commit.                                                                                                                                   | Do not replace them.                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `Iam\Mfa\FactorCodeCallers`                                                     | Itself                          | Scoped, under `iam.scoped:`                              | The caller each factor code was sent for.                                                                                                                                             | Do not replace it.                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `Iam\Audit\JobCallers`                                                          | Itself                          | Scoped                                                   | The caller a queued job carries into the audit trail.                                                                                                                                 | Do not replace it.                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| The `mfa` context namespace                                                     | `Iam\Mfa\MfaContextContributor` | Registered once booted                                   | Registered only while `iam.adapters.mfa` is on and no `mfa` contributor is registered, so yours is kept.                                                                              | Yours supplies the `mfa.*` keys of `Auth::context()` (`mfa.accepted`, `mfa.level` and the rest) that a policy reading the context relies on. One that answers them from anything but the proofs of the subject's own session (the request's, or a guard's, say) reports one session's verification for another's.                                                                                                                                                |
| The `sso` context namespace                                                     | `Iam\Sso\SsoContextContributor` | Registered once booted                                   | Registered only while `iam.adapters.sso` is on and no `sso` contributor is registered, so yours is kept.                                                                              | Yours supplies the `sso.*` keys of `Auth::context()` (`sso.connection` and `sso.link_provenance` among them) that anything reading the context relies on, a link confirmation of yours among them. One that answers them from anything but the provenance SSO stored with the session lets a session claim a connection or a link it never had.                                                                                                                  |
| SSO's `iam` check                                                               | `Iam\Checks\Sso\SsoBridgeCheck` | Registered with SSO                                      | Runs inside `sso:check`.                                                                                                                                                              | A check of yours under SSO's `iam` subject is kept, and takes this one out of SSO's boot, its worker commands and `sso:check`: SSO's boot then no longer refuses an application's `unlinked_handoffs` or a guard without `external_provider`, and the bridge runs only from `iam:check`. Do not register one.                                                                                                                                                    |
| `Iam\Bindings\BindingOutcome`                                                   | Itself                          | Shared instance                                          | Which seams the package bound and which kept the application's binding, read by `iam:check` for its notes and mandatory seams.                                                        | Do not replace it: `iam:check` would then report seams from a binding the package never made.                                                                                                                                                                                                                                                                                                                                                                    |
| `'iam.audit.registered'` (`Iam\Audit\AuditRegistrations::REGISTERED`)           | `true`                          | Instance, once the package has registered with audit-log | Read by the audit check, which reports *The audit mappers are not registered with laravel-audit-log* without it.                                                                      | Do not bind it: the audit check would then pass an application whose mappers never registered.                                                                                                                                                                                                                                                                                                                                                                   |
| `Iam\Audit\CallerContextContributor`, audit-log's context contributor           | Itself                          | Registered with audit-log once booted                    | Fills a record's actor, guard, principal, tenant and session from the caller a `jwt` or `api_key` guard holds, or a queued job carried, whatever the `iam.audit.mappers` switch says. | You cannot replace or remove it. A contributor of yours (`AuditLog::contribute()`, from a later provider's `boot()`) runs after it and fills only what it left, so it can add context but never change what this one filled. Fill the actor, principal, tenant or session from nothing but the caller the guard holds: on a record this one leaves open (no caller), one of yours that reads the request or `Auth::user()` names someone no guard authenticated. |

The listeners the package registers (the audit mappers, operational alerts, provisioning of an unlinked result, the
worker resets and the commit listeners) are described in [The audit trail](audit-trail.md),
[Provisioning and tenancy](provisioning-and-tenancy.md) and [Operations](operations.md).

## Mandatory seams still to come

`laravel-authentication`'s `Authentication\Contracts\ApplicationAccess`, `Authentication\Contracts\TenantAccess` and
`Authentication\Contracts\ScopeRegistry` will be answered from `laravel-authorization` once it can answer them. Until
then this package binds nothing over them and `iam:check` does not hold them mandatory, so they stay on
`laravel-authentication`'s defaults, which admit any principal to any application with any scope, and to its own
tenant only. Bind them yourself if that is not what your application means. See [Authorization](authorization.md).

Two more wait the same way, each on a member default that refuses rather than admits:

- `laravel-authorization`'s `Authorization\Contracts\SessionPolicySource`, which will be answered from the
  credential's scopes. Until then its `Authorization\Resolvers\NoSessionPolicy` allows a machine principal nothing;
  name your own at `authorization.session.source` if machines call routes it guards.
- Audit-log's `AuditLog\Contracts\AuditAccessPolicy`, which will be answered from `laravel-authorization`. Until then
  its `AuditLog\Access\DenyAllPolicy` shows nobody anything; bind your own to let a viewer read what its scope
  allows, scoping a tenant by `Reference::of('tenant', $tenantId)` as this package records it. Replacing it decides who
  reads every person's trail: a scope too wide shows one tenant's viewer every tenant's people (see
  [The audit trail](audit-trail.md#reading-the-trail)).

[authentication-extending]: https://github.com/sinemacula/laravel-authentication/blob/master/docs/guides/extending.md
[mfa-extending]: https://github.com/sinemacula/laravel-mfa/blob/master/docs/guides/extending.md
[sso-integrating]: https://github.com/sinemacula/laravel-sso/blob/master/docs/guides/integrating-with-laravel-iam.md
[sso-lock-order]: https://github.com/sinemacula/laravel-sso/blob/master/docs/guides/integrating-with-laravel-iam.md#the-lock-order
