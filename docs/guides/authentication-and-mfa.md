# Authentication and MFA

`laravel-authentication` owns who the caller is: identities, sessions, their proofs and their tokens. `laravel-mfa`
owns further factors: enrolment, verification, recovery codes and what a combination of proofs establishes. Neither
references the other. This package joins them through their seams, so a sign-in waits for a further factor on the
authentication session, a verification is recorded on that session, and one requirement answers everywhere it is
asked.

What each member does on its own is in its guides: MFA's [requirements][mfa-requirements],
[verification][mfa-verification], [enrolment][mfa-enrollment] and [middleware][mfa-middleware], and
`laravel-authentication`'s [signing in][auth-signing-in] and [sessions][auth-sessions]. This guide covers what the
package binds between them, why, and what that changes for your application.

## What is bound, and why

The package binds each seam below over its member's own default, and keeps any binding of your own. Every adapter
keeps nothing between calls. [Bindings](bindings.md) says, for each, how to replace it and what replacing it risks.

| Seam                                                       | Answered by                                                                  | So that                                                                                                                           |
|------------------------------------------------------------|------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------|
| Auth `AdditionalFactorPolicy`                              | MFA's requirement policy                                                     | a sign-in waits pending exactly when MFA requires a further factor                                                                |
| Auth `RequirementCheck`                                    | MFA's requirement check, over the session's proofs                           | one answer is shared by sign-in, a tenant's requirement, step-up and the gate                                                     |
| MFA `PendingSessionResolver`                               | `laravel-authentication`'s pending sessions                                  | a pending sign-in can verify its further factor                                                                                   |
| MFA `PendingCompletion`                                    | `satisfy()` on the pending session                                           | a verified factor activates the session, which issues its tokens                                                                  |
| MFA `StepUp`                                               | `stepUp()` on the session                                                    | a step-up is recorded on the session and returns a new access token                                                               |
| MFA `ProofStore`, `FirstFactorResolver`                    | the session's own proofs                                                     | proofs live on the authentication session, so a stateless guard works                                                             |
| Auth's `mfa` context namespace                             | MFA's own contributor, from the session's proofs                             | `Auth::context()` reports MFA's view of the session it was built for, in a request or a queued job                                |
| MFA `Reauthenticator`, `FreshnessGate`                     | `laravel-authentication`'s freshness policy                                  | freshness is judged once, by the session's proofs                                                                                 |
| MFA `FactorChangeGate`                                     | `factorChange()` under the session's lock                                    | a factor change takes a fresh step-up, judged as committed                                                                        |
| MFA `SessionRevoker` (mandatory)                           | `factorRemoved()` and `factorReset()`                                        | removing a factor or resetting an identity ends the sessions it should                                                            |
| MFA `SessionTransition`                                    | `factorChanged()`                                                            | a session short of its requirement after a change returns to pending                                                              |
| MFA `ChallengeGateway`, Auth `FactorCodeCounters`          | `laravel-authentication`'s factor codes, counted by MFA's challenge counters | MFA's email and SMS codes are issued and checked in one place, under MFA's limits (see [Codes and delivery](#codes-and-delivery)) |
| MFA `SmsSender`, `EmailSender`                             | your `OneTimeCodeSender`                                                     | a code MFA sends itself reaches the same sender as every other                                                                    |
| MFA `PasskeyGateway`, Auth `PasskeyFactorGate` (mandatory) | `laravel-authentication`'s passkeys                                          | a passkey is an MFA factor, and removing it takes its factor with it                                                              |
| MFA's context resolvers                                    | the validated session                                                        | MFA's events, active tenant, subject type and active state match the session                                                      |

The whole set is switched by `iam.adapters.mfa` (`IAM_ADAPTERS_MFA`). Leave it on unless you bind every one of these
seams yourself.

## Applications are guards

An MFA application is the `jwt` guard of the same name, and MFA hands each adapter its caller as plain values: the
identity (or pending session), the application and the client. Declare each MFA application as a guard (see
[Installation](installation.md#guards-and-applications)). Every MFA call for one that is no `jwt` guard is refused at
runtime with `SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException`, so `iam:check` reports it first, at
deploy: an MFA application that names no guard, and one whose guard is of another driver (see
[Checks](checks.md#configuration)).

## Signing in with a further factor

A sign-in through `laravel-authentication`'s session service asks MFA whether a further factor is owed. When it is, the
session starts pending, and its pending credential admits only the further factor:

```php
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;

$result = Auth::sessions('api')->signIn(
    'password',
    ['email' => $input['email'], 'password' => $input['password']],
    SignInContext::fromRequest($request),
);

$result->isPending(); // true while MFA still requires a further factor
```

The client then verifies the factor with its pending credential, on a route that declares it. MFA reads the pending
session through the package's resolver, verifies, and the completion activates the session as MFA's last write:

```php
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Verification\Submission;

// On a route behind `authentication.pending:mfa.verify,api`
$result = Mfa::verify(CallerContext::fromRequest($request, 'api'), Submission::factor($input['factor'], $input['code']));

$signIn = $result->completion(); // the SignInResult, with the session's tokens, once verified
```

The guard is bound, and the tokens are usable, only once MFA's transaction has committed. The whole route is in
[An example application](example-application.md#verifying-a-further-factor).

## Stepping up

An active session verifies a further factor the same way, with its access token. The package records the proof on
the authentication session (never in Laravel's session), so the next request with the same token meets the
requirement, on a stateless guard too, and no other session of the same person does. The completion is
`laravel-authentication`'s `AccessTokenResult`, holding the new access token.

A proof counts only while the identity still holds the factor that made it: an application that hands
`laravel-authentication` a step-up itself must name one of MFA's factors in it.

## One requirement

MFA's requirement check answers `laravel-authentication`'s requirement check, so the same answer decides whether a
sign-in waits pending, whether a tenant's requirement is met, and whether MFA's route gate lets a request on. Put the
gate on your own routes, after authentication:

```php
Route::middleware(['auth:api', 'mfa'])->group(function (): void {
    Route::get('/dashboard', DashboardController::class);
    Route::middleware('mfa:level=aal2')->get('/billing', BillingController::class);
});
```

The gate raises MFA's `InsufficientAuthenticationException`, which you answer in your exception handler (see MFA's
[middleware guide][mfa-middleware-answering]). Under `laravel-authorization`, put `mfa` before its middleware (see
[Authorization](authorization.md)).

## Factor changes and removal

Adding or removing a factor, and generating recovery codes, takes a fresh step-up, judged by `laravel-authentication`
under the session's lock; an identity's first additional factor takes a fresh reauthentication instead. Declare MFA's
freshness operations for each MFA application's guard (see [Installation](installation.md#guards-and-applications)). A
minimum assurance level in MFA's own freshness settings is refused with an `InvalidArgumentException`, since no stored
proof records a level.

Removing a factor ends every other session of the identity and voids the current session's proofs made with it;
resetting an identity ends all of its sessions. When the current session is returned to pending, the removal's
`completion()` carries its new pending credential back to the client. See MFA's [lifecycle guide][mfa-lifecycle].

## Codes and delivery

Bind `laravel-authentication`'s `OneTimeCodeSender`: it delivers every email and SMS code, MFA's included, and you write
every message's wording and template.

- MFA's challenge gateway sends and checks the code of every factor whose driver delivers by SMS or email through
  `laravel-authentication`'s factor codes. Its queued job hands the code to your sender with the purpose `mfa` or
  `enrollment`, and the type `sms` or `email`. A factor of any other channel is refused; rebind MFA's
  `ChallengeGateway` to send it with MFA's own.
- MFA's `SmsSender` and `EmailSender` forward to your sender in the same way, so a code MFA sends itself, once you rebind
  its `ChallengeGateway`, reaches it too, synchronously inside MFA's transaction.
- While an MFA application offers `sms` or `email`, the application does not boot until a `OneTimeCodeSender` is bound.

`laravel-authentication`'s own codes carry the identifier type (`email` or `phone`), so route `email` to email and
`phone` or `sms` to SMS. [Testing](testing.md) shows the fake senders.

## Passkeys

While an MFA application offers the `passkey` type, MFA's passkey ceremonies run through `laravel-authentication`'s
passkeys, so a passkey registered with an enrolment binding becomes a confirmed passkey factor. The passkey factor gate
is bound whatever the types say: removing a passkey through `laravel-authentication` takes its factor and association
with it, even once `passkey` is no longer offered. Configure `laravel-authentication`'s relying party
(`authentication.passkeys.relying_party`) before you offer the type.

## The context MFA reads

MFA's events, the active tenant whose requirement applies, the subject type and the active state are read from the
session `laravel-authentication` validated, never from a guard's ambient state. The active tenant is the one the
validated session recorded, so a tenant's requirement reaches MFA only for a session that acts in it.

`laravel-authentication`'s authentication context (`Auth::context()`) carries MFA's view of the session under `mfa`:
`mfa.accepted`, `mfa.multifactor`, `mfa.factor_types`, `mfa.level`, `mfa.phishing_resistant`, `mfa.user_verification`,
`mfa.last_verification_age_seconds` and `mfa.has_confirmed_factor`, the keys MFA's own contributor works out (see MFA's
[middleware guide][mfa-middleware]). This package registers the contributor while `iam.adapters.mfa` is on, unless you
registered your own under `mfa`, and `iam:check` requires the namespace either way.

The keys come from the session the context was built for and its proofs, never from the request: a context built for
another session, or in a queued job, reports that session's verification. A session that is pending, revoked or ended,
or no session at all, has the neutral context (nothing accepted, level `unclassified`).

`Auth::context()` is built once per guard per request and kept: a later read returns the kept context, which
`laravel-authentication` forgets only when the guard binds another identity, principal or session, or when this process
changes the session's proofs. A change another process commits does not reach a context already built. Its proofs are
read current, under the session row's lock, only when that first build happens inside a transaction on the session
model's connection; once it is built, a read inside a transaction takes no lock and reads nothing. Where you need an
answer inside a transaction that is current and holds under the lock, ask there through
`Auth::sessions($guard)->proofs()` and `firstFactor()`, or MFA's own view, `Mfa::authenticationContext($caller)`, which
is worked out afresh on each call, rather than `Auth::context()`.

```php
use SineMacula\Laravel\Authentication\Facades\Auth;

if (Auth::context()?->get('mfa.accepted') !== true) {
    // Ask for a further factor before going on.
}
```

`Mfa::authenticationContext()` still answers MFA's view of the caller the request serves, the same keys.

## Transactions and retries

MFA opens the transaction of each of its changes itself (a verification, a factor change, a removal, a reset), and the
adapters run inside it, so those flows cannot be wrapped:

- never call one of them inside `Iam::transaction()`, or inside any transaction you open;
- when one fails to serialise or deadlocks, retry the request: MFA never retries, and only the outermost transaction
  can be.

Tell a concurrency failure by asking Laravel's detector, rather than by catching one exception class, and walk the
exception's previous ones too, since a nested transaction wraps it:

```php
use Illuminate\Contracts\Database\ConcurrencyErrorDetector;

$retryable = app(ConcurrencyErrorDetector::class)->causedByConcurrencyError($exception);
```

See [Operations](operations.md#retries).

## Testing

MFA's `actingAsVerified()` works under this package: the package binds the recorder it begins its sign-in and records
its proofs through, which starts the identity's session from a password first factor and steps it up, or completes it
when it waits on a further factor, through `laravel-authentication`, since the proof store refuses the helper's own
proofs. This package's `InteractsWithIam` helpers arrange more of the caller (see
[Testing](testing.md)).

## Further reading

- [Bindings](bindings.md): replacing each adapter, and what it risks.
- [The authentication and MFA design note](../design/authentication-and-mfa.md): the adapters, translations and lock
  order.
- [The codes, delivery and passkeys design note](../design/codes-delivery-and-passkeys.md): code challenges, code
  delivery, passkeys and the context MFA reads.
- MFA's guide [within `laravel-iam`][mfa-within-iam], and its [extending guide][mfa-extending].

[mfa-requirements]: https://github.com/sinemacula/laravel-mfa/blob/master/docs/guides/requirements.md
[mfa-verification]: https://github.com/sinemacula/laravel-mfa/blob/master/docs/guides/verification.md
[mfa-enrollment]: https://github.com/sinemacula/laravel-mfa/blob/master/docs/guides/enrollment.md
[mfa-middleware]: https://github.com/sinemacula/laravel-mfa/blob/master/docs/guides/middleware.md
[mfa-middleware-answering]: https://github.com/sinemacula/laravel-mfa/blob/master/docs/guides/middleware.md#answering
[mfa-lifecycle]: https://github.com/sinemacula/laravel-mfa/blob/master/docs/guides/lifecycle.md
[mfa-within-iam]: https://github.com/sinemacula/laravel-mfa/blob/master/docs/guides/installation.md#within-laravel-iam
[mfa-extending]: https://github.com/sinemacula/laravel-mfa/blob/master/docs/guides/extending.md
[auth-signing-in]: https://github.com/sinemacula/laravel-authentication/blob/master/docs/guides/signing-in.md
[auth-sessions]: https://github.com/sinemacula/laravel-authentication/blob/master/docs/guides/sessions.md
