# Authentication and SSO

`laravel-sso` runs a sign-in through a tenant's own identity provider and ends it with a single-use handoff code.
`laravel-authentication` owns the session that sign-in becomes. This package redeems the code and writes the session in
one transaction, answers SSO's contracts from `laravel-authentication`'s sessions, and ends exactly the sessions an SSO
change concerns.

SSO's own behaviour is in its guides: [starting a flow][sso-starting], [completing a flow][sso-completing],
[redeeming a handoff][sso-redeeming], [links][sso-links], [re-authenticating][sso-reauthenticating],
[enforcement][sso-enforcement] and [freshness][sso-freshness]. SSO's [guide for this package][sso-iam] is the
specification the adapters are written to. This guide covers what you call, and what the package does for you.

## What is bound, and why

| Seam                                       | Answered by                                                       | So that                                                                            |
|--------------------------------------------|-------------------------------------------------------------------|------------------------------------------------------------------------------------|
| SSO `SessionRevocation` (mandatory)        | `laravel-authentication`'s revocations                            | a change to a connection, a link, a scope or enforcement ends its sessions         |
| Auth `ExternalIdentityLinks`               | the redemption SSO admitted in this request alone                 | a sign-in finds exactly the identity SSO's link names                              |
| SSO `Linker` and `LinkStorage`             | SSO's own link store                                              | links can be made, found and removed                                               |
| SSO `ReauthenticationSessions`             | `laravel-authentication`'s sessions                               | a session held to a tenant's rule can renew at its provider                        |
| Auth `ExternalEvidencePolicy`              | the evidence SSO accepted, then MFA's combination policy          | a provider's evidence counts only through both (see [MFA and SSO](mfa-and-sso.md)) |
| SSO `Freshness`                            | `laravel-authentication`'s freshness policy                       | SSO's sensitive changes ask for a fresh session, as your own do                    |
| SSO `ApplicationPolicy`                    | the guard's sign-in methods                                       | a guard that does not allow `external_provider` starts no flow                     |
| SSO `LinkEmailMatcher`                     | `laravel-authentication`'s verified identifiers                   | linking by a verified domain matches only a verified email address                 |
| SSO `LinkConfirmation`                     | how the caller's session signed in, from its proofs               | only a session apart from every provider confirms a verified domain link           |
| Auth `TenantAuthenticationPolicy`          | SSO's enforcement and exemptions, and your MFA tenant requirement | one tenant policy decides every session acting in the tenant                       |
| The `sso` authentication context namespace | the provenance SSO captured at sign-in                            | `Auth::context()` says how a session began                                         |

SSO's handoff codes stay SSO's own: the package never binds a handoff issuer. The membership and tree seams are in
[Provisioning and tenancy](provisioning-and-tenancy.md). The whole set is switched by `iam.adapters.sso`
(`IAM_ADAPTERS_SSO`); see [Bindings](bindings.md) for replacing each and what that risks.

## Applications and guards

An SSO application is the `jwt` guard of the same name. Allow `external_provider` among that guard's methods, and leave
SSO's `unlinked_handoffs` off for it: under this package a sign-in that resolves to no identity is provisioned or
refused, never handed off (see [Installation](installation.md#guards-and-applications)). `iam:check` refuses either.

## Redeeming a sign-in

Every `sign_in` code is redeemed through one call, with plain values you read from the request:

```php
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Iam\Facades\Iam;

$result = Iam::signIns()->redeem(
    $input['application'],
    $input['connection'],
    $input['code'],
    $input['verifier'],
    SignInContext::fromRequest($request),
);
```

In one transaction on the storage connection it resolves the application to its guard, has SSO admit the code under
SSO's locks, and signs the linked identity in once, on that guard, writing the session last. It answers:

- SSO's `RedemptionResult` when SSO refused the code (unknown, replayed, a mismatching verifier, rate limited and the
  rest). The refusal commits, so the code is spent and the client starts again.
- `laravel-authentication`'s `SignInResult` once the session committed, active or pending. A pending session is an
  outcome, not a failure: the person owes a further factor (see [Authentication and MFA](authentication-and-mfa.md)).

It throws, and rolls everything back with the code unspent, when:

- `laravel-authentication` refuses the sign-in: `ExternalSignInRefusedException`, whose `$result` is the failed
  `SignInResult` to answer the client from;
- the result is linked to no identity: `UnlinkedSignInException`;
- the application is no `jwt` guard: `UnresolvedReferenceException`.

A serialisation failure, a deadlock or SSO's own `LinkCandidatesChanged` runs the whole redemption again, up to
`iam.transactions.attempts`. Send the credential only once the call has returned, with `Cache-Control: no-store`
(`SecretResponse::json()` sets it). Call it with no transaction of your own open: inside one it joins it, and a
concurrency failure is rethrown for you to retry. The full route is in
[An example application](example-application.md#signing-in-through-sso).

## Re-authenticating

A `reauthenticate` code renews the session it was started on, once, at the provider:

```php
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Iam\Facades\Iam;

$result = Iam::reauthentications()->redeem(
    $input['application'],
    $input['connection'],
    $input['code'],
    $input['verifier'],
    ClientContext::fromRequest($request),
);
```

It answers SSO's refusal, committed, or `laravel-authentication`'s `AccessTokenResult` with the renewed session's new
access token. The session renewed is the one the code names, never the one the request is authenticated with, so tell
the caller they are fresh only when `$result->session` is their own. A refusal by `laravel-authentication` throws
`ExternalReauthenticationRefusedException`, carrying the failed result, with the code unspent. Redeem `reauthenticate`
codes through this call alone: SSO's own `admit()` refuses one.

## Linking an identity

A `link` code joins the caller's identity to a provider's subject. It writes no session, so it is redeemed on its own,
for the caller your authentication established:

```php
use Illuminate\Auth\AuthenticationException;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Iam\Facades\Iam;

$caller = Auth::caller() ?? throw new AuthenticationException;

$result = Iam::links()->redeem(
    $input['connection'],
    $input['code'],
    $input['verifier'],
    ClientContext::fromRequest($request),
    $caller,
);
```

Holding the code and its verifier proves which client started the flow, not who is calling now, so the caller is a
value you hand in, never read by the package: `Auth::caller()` reads it from the request, and its guard is the
application the link is redeemed for. SSO asks three things of the link:

- **Freshness.** The session the caller holds must be its own and fresh for `sso.link.create`; a caller with no
  session, or one redeemed inside a transaction of your own, is not, since that snapshot may be older than the call.
- **Eligibility.** A link is allowed only by an accepted membership of the connection's tenant, answered from your
  memberships (see [Provisioning and tenancy](provisioning-and-tenancy.md#memberships)). Without them every link is
  refused as `link_ineligible`.
- **Link confirmation.** An identity that holds, or has ever held, a link by a verified domain may link a provider, or
  confirm that link, only once SSO's `SineMacula\Laravel\Sso\Contracts\LinkConfirmation` says the caller's
  authentication is independent of it, or the `link` is refused as `independent_authentication_required`. The package
  answers it in place of SSO's `SineMacula\Laravel\Sso\Linking\RefusingLinkConfirmation`, from the proofs and the
  provenance `laravel-authentication` records for the session the caller holds, its own: the session is independent
  when it signed in with a password or a passkey, or through your own account recovery, was never renewed through a
  provider, and records no link by a verified domain. A session any provider established is not, whichever link it
  stood on, so a person whose only session
  came through their verified domain link signs in with a password or a passkey first
  ([laravel-sso: confirming it is the person][sso-links-confirming]).

A recovery session counts only when your recovery starts it with `Auth::sessions($guard)->start()` from a `FirstFactor`
on the `recovery` channel (`ChannelKind::RECOVERY`, which `laravel-authentication` admits as a first factor only); a
session started on any other channel, `unknown` included, does not. What a password, a passkey or your recovery proves
is yours to keep true: one enrolled from a session the verified domain link established, or a recovery its provider can
drive, proves nothing the provider could not do. A caller with no session of its own, and a session that is pending,
revoked or ended, never confirms. Inside SSO's transaction the session's row is locked until the link commits, so
revoking the session waits for it. Freshness renewed through a provider never counts here, whatever SSO's `Freshness`
answers.

## SSO's own calls that ask for freshness

SSO asks for a fresh session before its sensitive changes (a connection's trust, enabling or disabling it, a key's
rotation, a domain's claim, the enforcement rule, a link's removal) and before a `link` flow starts, and judges the
caller each of those calls is handed. The package never takes one from the request, so hand SSO the caller as it names
it:

```php
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;

$result = app(AuthorizationRequestService::class)->start(
    // ...the start's own arguments, then
    Iam::callers()->of($caller),
);
```

`$caller` is the `Auth::caller()` of the request. `Iam::callers()->of()` names its identity as SSO names it, with the
session that caller's access credential holds, and only while it is a session of the caller's own guard that the
caller's identity owns; the package never asks the guard. SSO's freshness judges that session alone, and only while it
is live and the caller's identity's. A caller signed in with a refresh or pending credential, or one holding a session
of another guard or identity, is `stale`. Without a caller it answers `stale`, and SSO refuses with
`freshness_required`. Declare SSO's operations for the guard (see
[Installation](installation.md#guards-and-applications)).

Call `Iam::callers()->of()` with no transaction open on the storage connection, never inside `Iam::transaction()` or a
transaction of your own: a caller named inside one carries no session, so it is `stale`, since that transaction's
snapshot may be older than the call and the session's row cannot be locked where SSO asks. So a freshly stepped-up
caller still meets `freshness_required` there. Do not loosen the `sso.*` freshness entries for it: move the call out of
the transaction, and write your own bookkeeping in a transaction after it.

## Revocation

Nothing is yours to call. When a connection is disabled or deleted, a link is removed, a scope is widened or a tenant's
enforcement changes, SSO asks the package to revoke inside its own transaction, and exactly the sessions the change
concerns end with it. An enforcement change judges the sessions acting in the tenant against the tenant policy, once
in SSO's transaction and once more after it commits, so a session that entered the tenant meanwhile is judged too.
With a tenant tree named, every tenant below the enforcing one is judged as well.

Bind `laravel-authentication`'s `TenantResolver` before you turn enforcement on: its default resolves no tenant, and
every enforcement change then throws. See `laravel-authentication`'s [extending guide][auth-extending].

## The tenant policy

`laravel-authentication`'s tenant authentication policy is answered from SSO's enforcement, SSO's exemption gate and
your MFA `TenantRequirement` together, with a version that changes whenever any of them does. A session that signed in
through a connection the tenant's rule accepts meets it; an exempt identity's session is answered without one; any
other is refused as `sso_required`, or owes a further factor.

SSO revokes only for a change of its own rules. Whenever your `EnforcementExemption` grants or withdraws an identity's
exemption, report it for every tenant concerned, inside the transaction that writes it:

```php
use SineMacula\Laravel\Iam\Facades\Iam;

Iam::transaction(function () use ($tenant): void {
    // ...write the exemption
    Iam::tenantPolicies()->changed($tenant);
});
```

The same call reports a change to your MFA tenant requirement (see
[Provisioning and tenancy](provisioning-and-tenancy.md#the-tenant-mfa-requirement)).

## Provenance and the `sso` context

A session SSO established keeps how it began, written once with the session and never rewritten. Read it through
`laravel-authentication`'s authentication context:

```php
use SineMacula\Laravel\Authentication\Facades\Auth;

$connection = Auth::context()?->get('sso.connection');
```

A session no provider established has no `sso` keys at all; one that SSO established has all twelve, `null` where the
sign-in did not state a fact. The keys are history, never a current check: they say how the session began, not whether
it is still allowed. Every key is in SSO's [session provenance guide][sso-provenance].

## Mapped attributes

What a connection's attribute mapping carries is profile data, never what selects an identity. Besides SSO's standard
targets, declare in `sso.mapping.custom_attributes` the custom keys your code reads, for example
`['department', 'employee_number']`; a mapping naming any other custom key is refused. Your provisioner reads them
from the result (`$result->attributes`); see [Provisioning and tenancy](provisioning-and-tenancy.md#provisioning) and
SSO's [managing connections guide][sso-managing-connections]. No check can see a connection's mapping, which is a
database row, so this is yours to keep right.

## Routes

The package ships no routes. SSO's start, completion and metadata routes are SSO's, laid out in its
[example application][sso-example]; the redemption routes call the services above.
[An example application](example-application.md) puts them together.

## Transactions and locks

- The sign-in and re-authentication redemptions run in one transaction on the storage connection, retried whole; a
  `link` runs through SSO's standalone redemption.
- SSO's starts and completions talk to the provider and refuse to run inside a transaction: never wrap them.
- Every adapter takes its locks in SSO's lock order, with `laravel-authentication`'s session row last. Your own
  contracts that SSO asks under its locks (memberships, link eligibility) come after SSO's, so take no lock on rows
  other writers share there. The order is in SSO's [guide for this package][sso-iam-locks].

## Further reading

- [The SSO redemption and revocation design note](../design/sso-redemption-and-revocation.md).
- [The tenant authentication policy design note](../design/tenant-authentication-policy.md).

[sso-starting]: https://github.com/sinemacula/laravel-sso/blob/master/docs/guides/starting-a-flow.md
[sso-completing]: https://github.com/sinemacula/laravel-sso/blob/master/docs/guides/completing-a-flow.md
[sso-redeeming]: https://github.com/sinemacula/laravel-sso/blob/master/docs/guides/redeeming-a-handoff.md
[sso-links]: https://github.com/sinemacula/laravel-sso/blob/master/docs/guides/links.md
[sso-links-confirming]: https://github.com/sinemacula/laravel-sso/blob/master/docs/guides/links.md#confirming-it-is-the-person
[sso-reauthenticating]: https://github.com/sinemacula/laravel-sso/blob/master/docs/guides/reauthenticating.md
[sso-enforcement]: https://github.com/sinemacula/laravel-sso/blob/master/docs/guides/enforcement.md
[sso-freshness]: https://github.com/sinemacula/laravel-sso/blob/master/docs/guides/freshness.md
[sso-iam]: https://github.com/sinemacula/laravel-sso/blob/master/docs/guides/integrating-with-laravel-iam.md
[sso-iam-locks]: https://github.com/sinemacula/laravel-sso/blob/master/docs/guides/integrating-with-laravel-iam.md#the-lock-order
[sso-provenance]: https://github.com/sinemacula/laravel-sso/blob/master/docs/guides/session-provenance.md
[sso-managing-connections]: https://github.com/sinemacula/laravel-sso/blob/master/docs/guides/managing-connections.md
[sso-example]: https://github.com/sinemacula/laravel-sso/blob/master/docs/guides/example-application.md
[auth-extending]: https://github.com/sinemacula/laravel-authentication/blob/master/docs/guides/extending.md
