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

| Seam                                                       | Answered by                                                                                                           | So that                                                                                                                           |
|------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------|
| Auth `AdditionalFactorPolicy`                              | MFA's requirement policy                                                                                              | a sign-in waits pending exactly when MFA requires a further factor                                                                |
| Auth `RequirementCheck`                                    | MFA's requirement check, over the session's proofs                                                                    | one answer is shared by sign-in, a tenant's requirement, step-up and the gate                                                     |
| MFA `PendingSessionResolver`                               | `laravel-authentication`'s pending sessions                                                                           | a pending sign-in can verify its further factor                                                                                   |
| MFA `PendingCompletion`                                    | `satisfy()` on the pending session                                                                                    | a verified factor activates the session, which issues its tokens                                                                  |
| MFA `StepUp`                                               | `stepUp()` on the session                                                                                             | a step-up is recorded on the session and returns a new access token                                                               |
| MFA `ProofStore`, `FirstFactorResolver`                    | the session's own proofs                                                                                              | proofs live on the authentication session, so a stateless guard works                                                             |
| MFA `Reauthenticator`, `FreshnessGate`                     | `laravel-authentication`'s freshness policy                                                                           | freshness is judged once, by the session's proofs                                                                                 |
| MFA `FactorChangeGate`                                     | `factorChange()` under the session's lock                                                                             | a factor change takes a fresh step-up, judged as committed                                                                        |
| MFA `SessionRevoker` (mandatory)                           | `factorRemoved()` and `factorReset()`                                                                                 | removing a factor or resetting an identity ends the sessions it should                                                            |
| MFA `SessionTransition`                                    | `factorChanged()`                                                                                                     | a session short of its requirement after a change returns to pending                                                              |
| MFA `ChallengeGateway`, Auth `FactorCodeCounters`          | `laravel-authentication`'s factor codes, counted by MFA's challenge counters, while its one-time code sender is bound | MFA's email and SMS codes are issued and checked in one place, under MFA's limits (see [Codes and delivery](#codes-and-delivery)) |
| MFA `PasskeyGateway`, Auth `PasskeyFactorGate` (mandatory) | `laravel-authentication`'s passkeys                                                                                   | a passkey is an MFA factor, and removing it takes its factor with it                                                              |
| MFA `TenantRequirement`                                    | your tenant MFA requirement                                                                                           | a tenant's requirement reaches MFA (see [Provisioning and tenancy](provisioning-and-tenancy.md))                                  |
| MFA's context resolvers                                    | the validated session                                                                                                 | MFA's events, active tenant, subject type and active state match the session                                                      |

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

Adding, replacing or removing a factor, and generating recovery codes, takes a fresh step-up, judged by
`laravel-authentication` under the session's lock; an identity's first additional factor takes a fresh
reauthentication instead. Declare MFA's freshness operations for each MFA application's guard (see
[Installation](installation.md#guards-and-applications)). A minimum assurance level in MFA's own freshness settings is
refused with an `InvalidArgumentException`, since no stored proof records a level.

Removing a factor ends every other session of the identity and voids the current session's proofs made with it;
resetting an identity ends all of its sessions. When the current session is returned to pending, the removal's
`completion()` carries its new pending credential back to the client. See MFA's [lifecycle guide][mfa-lifecycle].

## Codes and delivery

Both members' codes reach your gateways as one neutral message, `SineMacula\Laravel\Iam\Delivery\CodeMessage`, and you
write every message's wording and template. Name a gateway for each channel you use:

```php
// config/iam.php
'delivery' => [
    'email' => App\Delivery\MailCodes::class,  // implements SineMacula\Laravel\Iam\Contracts\EmailGateway
    'sms'   => App\Delivery\TextCodes::class,  // implements SineMacula\Laravel\Iam\Contracts\SmsGateway
    'types' => [
        'email' => 'email',
        'phone' => 'sms',
    ],
],
```

- Naming a gateway points MFA's sender of that channel at it. `laravel-authentication`'s one-time code sender is
  pointed at the gateways once every gateway `types` routes to is named; `types` maps each identifier type to a
  channel.
- An MFA code for one of MFA's own `email` or `sms` factors is issued through `laravel-authentication`'s factor codes
  only while `laravel-authentication`'s one-time code sender is bound: this package binds it once every gateway `types`
  routes to is named (or bound before this package registers), or you bind your own sender. It is then delivered from
  `laravel-authentication`'s queued job once the code has committed: a gateway that throws fails the job, and your
  queue retries it under its own policy. Otherwise MFA sends the code itself, synchronously, inside MFA's transaction,
  so a gateway that throws leaves no code and nothing is queued or retried. Naming only `iam.delivery.email` with the
  shipped `types` (`phone` routed to `sms`) is such a case: MFA's email codes then go out from MFA's own transaction.
- A gateway's return means the message was accepted for delivery, not received. The package never queues or retries a
  delivery itself.
- With no gateway named, MFA keeps its own senders, which refuse to send, and refuses to boot while an application
  offers `sms` or `email` factors.

The message carries the application, its `purpose` (`SineMacula\Laravel\Iam\Delivery\Enums\Purpose`), its `source`,
its `channel`, the `code` (a `Secret`, revealed with `reveal()`), `expiresAt`, and the `destination()` and
`recipient()`, which a dump never shows. [An example application](example-application.md#a-gateway) shows a gateway,
and [Testing](testing.md) the fakes. How each delivery runs and what it locks is in the
[codes and delivery design note](../design/codes-delivery-and-passkeys.md).

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

`laravel-authentication`'s authentication context (`Auth::context()`) has no `mfa` namespace yet: a later release of
this package contributes it, from the session's proofs, and `iam:check` then requires it beside `sso`. Until then read
MFA's own view of a caller with `Mfa::authenticationContext()`.

## Transactions and retries

MFA opens the transaction of each of its changes itself (a verification, a factor change, a removal, a reset), and the
adapters run inside it, so those flows cannot be wrapped:

- never call one of them inside `Iam::transaction()`, or inside any transaction you open;
- when one fails to serialise or deadlocks, retry the request: MFA never retries, and only the outermost transaction
  can be.

Tell a concurrency failure by asking Laravel's detector, rather than by catching one exception class, since what
reaches you depends on where the statement ran:

```php
use Illuminate\Contracts\Database\ConcurrencyErrorDetector;

$retryable = app(ConcurrencyErrorDetector::class)->causedByConcurrencyError($exception);
```

Walk the exception's previous ones too, as `Iam::transaction()` does. See [Operations](operations.md#retries).

## Testing

MFA's `actingAsVerified()` does not work under this package: it records its proof through the proof store, which
refuses it. Use this package's `InteractsWithIam` helpers instead (see [Testing](testing.md)).

## Further reading

- [Bindings](bindings.md): replacing each adapter, and what it risks.
- [The authentication and MFA design note](../design/authentication-and-mfa.md): every adapter, translation and lock.
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
