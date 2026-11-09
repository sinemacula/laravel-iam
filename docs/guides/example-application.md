# An Example Application

The package ships no routes, controllers or views. This guide lays out one API that serves the flows this package
changes, to show how the pieces meet: which routes are public, which belong to the caller, which are for
administrators, the order of their middleware, and which one core method each controller calls. The flows it leaves
to the members' own guides (refreshing, signing out, enrolment, factor changes and recovery codes) are listed in
[Flows the members lay out](#flows-the-members-lay-out), with what this package changes in each.

**It is an example, never shipped.** Every class under `App\` is the example application's own: replace its
controllers, models and messages with yours. Every class outside `App\` is a member's or this package's, used as it is.
Each controller reads the request only to build the plain values it hands over (`SignInContext::fromRequest()`,
`ClientContext::fromRequest()`, `Auth::caller()`); nothing it calls reads the request itself. SSO's own start,
completion and metadata routes are laid out in SSO's [example application][sso-example] and are not repeated here.

## The routes

| Method | Path                                         | Access                      | Calls                                       |
|--------|----------------------------------------------|-----------------------------|---------------------------------------------|
| `POST` | `/api/auth/sessions`                         | public                      | `Auth::sessions()->signIn()`                |
| `POST` | `/api/auth/sessions/pending/codes`           | pending credential          | `Mfa::sendCode()`                           |
| `POST` | `/api/auth/sessions/pending/verifications`   | pending credential          | `Mfa::verify()`, completing the sign-in     |
| `POST` | `/api/auth/sso/sessions`                     | public                      | `Iam::signIns()->redeem()`                  |
| `POST` | `/api/mfa/verifications`                     | caller                      | `Mfa::verify()`, a step-up                  |
| `POST` | `/api/auth/sso/reauthentications`            | caller                      | `Iam::reauthentications()->redeem()`        |
| `POST` | `/api/auth/sso/links/authorization-requests` | caller (fresh)              | `Iam::callers()->run()` around SSO's start  |
| `POST` | `/api/auth/sso/links`                        | caller                      | `Iam::links()->redeem()`                    |
| `POST` | `/api/sso/connections/{connection}/enable`   | administrator               | `Iam::callers()->run()` around SSO's change |
| `POST` | `/api/invoices/{invoice}/refund`             | caller, step-up, permission | your own action                             |

## The routes file

```php
use App\Http\Controllers\ConnectionController;
use App\Http\Controllers\InvoiceRefundController;
use App\Http\Controllers\PendingSignInController;
use App\Http\Controllers\SignInController;
use App\Http\Controllers\SsoLinkController;
use App\Http\Controllers\SsoReauthenticationController;
use App\Http\Controllers\SsoSignInController;
use App\Http\Controllers\StepUpController;
use Illuminate\Support\Facades\Route;

Route::post('/auth/sessions', SignInController::class);
Route::post('/auth/sso/sessions', SsoSignInController::class);

Route::middleware('authentication.pending:mfa.send_code,api')
    ->post('/auth/sessions/pending/codes', [PendingSignInController::class, 'sendCode']);
Route::middleware('authentication.pending:mfa.verify,api')
    ->post('/auth/sessions/pending/verifications', [PendingSignInController::class, 'verify']);

Route::middleware(['auth:api', 'mfa'])->group(static function (): void {
    Route::middleware('mfa.exempt')->post('/mfa/verifications', StepUpController::class);

    Route::post('/auth/sso/reauthentications', SsoReauthenticationController::class);
    Route::post('/auth/sso/links/authorization-requests', [SsoLinkController::class, 'start']);
    Route::post('/auth/sso/links', [SsoLinkController::class, 'store']);

    Route::middleware(['mfa:level=aal2', 'permission:sso:manage'])
        ->post('/sso/connections/{connection}/enable', [ConnectionController::class, 'enable']);

    Route::middleware(['mfa:level=aal2', 'authorize:invoices:refund,invoice'])
        ->post('/invoices/{invoice}/refund', InvoiceRefundController::class);
});
```

- **Public.** A sign-in and the SSO sign-in redemption take no session: a password, or a handoff code and its verifier,
  authenticates them.
- **The pending credential.** `authentication.pending:<action>,api` declares that the route authenticates with a
  pending session's credential for that one action, so a pending sign-in reaches only the further factor.
- **The caller's own.** Everything else is behind `auth:api`, then MFA's gate, `mfa`. The step-up route itself is
  exempt from the gate (`mfa.exempt`), since it is how the requirement is met.
- **MFA's gate before `laravel-authorization`'s middleware.** `mfa` comes after authentication and before
  `laravel-authorization`'s `permission:`, `authorize:` and `role:`, so a request that is not signed in strongly enough
  is answered with a step-up before it can be denied. The step-up a whole route needs is stated with `mfa:level=` or
  `mfa:operation=`; one a policy statement states with an `authentication_requirement` is answered with the same
  step-up response, MFA's (see [Authorization](authorization.md#step-up-before-authorization)).
- **No tenant isolation from `authorize:` or `permission:` yet.** The refund route checks the caller's grants in its
  active tenant and nothing of the invoice's tenant, so a tenant's administrator granted `invoices:refund` could refund
  another tenant's invoice by its id. Have the invoice name its tenant, or bind your own resource tenant resolver, or
  scope the bound invoice to the caller's tenant, before you rely on the route to keep tenants apart (see
  [Authorization](authorization.md#tenants)).

## Signing in with a password

```php
namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Secrets\SecretResponse;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;

final class SignInController
{
    public function __invoke(Request $request): JsonResponse
    {
        /** @var array{email: string, password: string} $input */
        $input = $request->validate([
            'email'    => ['required', 'string'],
            'password' => ['required', 'string'],
        ]);

        $result = Auth::sessions('api')->signIn('password', $input, SignInContext::fromRequest($request));

        if ($result->isFailed()) {
            abort(401);
        }

        // Pending: MFA requires a further factor before any token is issued
        return $result->isPending()
            ? SecretResponse::json(['status' => 'pending', 'pending_credential' => $result->credential])
            : SecretResponse::json([
                'access_token'  => $result->session?->tokens->accessToken,
                'refresh_token' => $result->session?->tokens->refreshToken,
                'expires_in'    => $result->session?->tokens->expiresIn,
            ]);
    }
}
```

`SecretResponse::json()` reveals the secrets into the body and sends it with `Cache-Control: no-store`. How to answer
a rate-limited sign-in, and every other result, is in `laravel-authentication`'s [signing in guide][auth-signing-in].

## Verifying a further factor

The pending client lists or is sent a factor, then verifies it with its pending credential in the body:

```php
namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use SineMacula\Laravel\Authentication\Secrets\SecretResponse;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Verification\Submission;

final class PendingSignInController
{
    public function sendCode(Request $request): JsonResponse
    {
        $sent = Mfa::sendCode(CallerContext::fromRequest($request, 'api'), $request->input('factor'));

        return $sent->wasSent()
            ? response()->json(['challenge' => $sent->challengeId, 'expires_at' => $sent->expiresAt])
            : response()->json(['reason' => $sent->reason?->value, 'retry_after' => $sent->retryAfter], 422);
    }

    public function verify(Request $request): JsonResponse
    {
        /** @var array{factor: string, challenge: string, code: string} $input */
        $input = $request->validate([
            'factor'    => ['required', 'string'],
            'challenge' => ['required', 'string'],
            'code'      => ['required', 'string'],
        ]);

        $result = Mfa::verify(
            CallerContext::fromRequest($request, 'api'),
            Submission::challenge($input['factor'], $input['challenge'], $input['code']),
        );

        $signIn = $result->completion();

        if ($result->isFailed() || !$signIn instanceof SignInResult || !$signIn->isSignedIn()) {
            return response()->json(['reason' => $result->reason?->value], 422);
        }

        return SecretResponse::json([
            'access_token'  => $signIn->session?->tokens->accessToken,
            'refresh_token' => $signIn->session?->tokens->refreshToken,
            'expires_in'    => $signIn->session?->tokens->expiresIn,
        ]);
    }
}
```

The package activates the session as MFA's last write, and the tokens are issued only once MFA's transaction has
committed. Never wrap `Mfa::verify()` in a transaction of your own; on a concurrency failure, retry the request (see
[Operations](operations.md#retries)).

## Stepping up

```php
namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use SineMacula\Laravel\Authentication\Secrets\SecretResponse;
use SineMacula\Laravel\Authentication\Sessions\AccessTokenResult;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Verification\Submission;

final class StepUpController
{
    public function __invoke(Request $request): JsonResponse
    {
        /** @var array{factor: string, code: string} $input */
        $input = $request->validate([
            'factor' => ['required', 'string'],
            'code'   => ['required', 'string'],
        ]);

        $result = Mfa::verify(CallerContext::fromRequest($request, 'api'), Submission::factor($input['factor'], $input['code']));
        $token  = $result->completion();

        return $token instanceof AccessTokenResult && $token->isIssued()
            ? SecretResponse::json(['access_token' => $token->accessToken, 'expires_at' => $token->expiresAt])
            : response()->json(['reason' => $result->reason?->value], 422);
    }
}
```

The proof is recorded on the authentication session, so the new access token, and the old one, now meet the
requirement on the next request.

## Signing in through SSO

The client completes SSO's flow, receives a handoff code on its redirect URI, and posts it with its verifier:

```php
namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use SineMacula\Laravel\Authentication\Secrets\SecretResponse;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Iam\Exceptions\ExternalSignInRefusedException;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;

final class SsoSignInController
{
    public function __invoke(Request $request): JsonResponse
    {
        /** @var array{application: string, connection: string, code: string, verifier: string} $input */
        $input = $request->validate([
            'application' => ['required', 'string'],
            'connection'  => ['required', 'string'],
            'code'        => ['required', 'string'],
            'verifier'    => ['required', 'string'],
        ]);

        try {
            $result = Iam::signIns()->redeem(
                $input['application'],
                $input['connection'],
                $input['code'],
                $input['verifier'],
                SignInContext::fromRequest($request),
            );
        } catch (ExternalSignInRefusedException $refused) {
            // Rolled back: the code is unspent, and nothing reports a sign-in
            return response()->json(['reason' => $refused->result->reason?->value], 401);
        }

        if ($result instanceof RedemptionResult) {
            // SSO refused the code, and the refusal committed: the client starts again
            return response()->json(['reason' => $result->reason?->value], $result->isRateLimited() ? 429 : 400);
        }

        return $result->isPending()
            ? SecretResponse::json(['status' => 'pending', 'pending_credential' => $result->credential])
            : SecretResponse::json([
                'access_token'  => $result->session?->tokens->accessToken,
                'refresh_token' => $result->session?->tokens->refreshToken,
                'expires_in'    => $result->session?->tokens->expiresIn,
            ]);
    }
}
```

The code is consumed and the session written in one transaction the package opens, retried whole on a concurrency
failure, and the credential leaves only after it commits. A pending SSO session verifies its further factor through the
same pending routes as a password sign-in. Send `Retry-After` with a rate-limited answer, from `$result->retryAfter`.

## Re-authenticating through SSO

```php
namespace App\Http\Controllers;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Iam\Exceptions\ExternalReauthenticationRefusedException;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;

final class SsoReauthenticationController
{
    public function __invoke(Request $request): JsonResponse
    {
        $caller = Auth::caller() ?? throw new AuthenticationException;

        /** @var array{application: string, connection: string, code: string, verifier: string} $input */
        $input = $request->validate([
            'application' => ['required', 'string'],
            'connection'  => ['required', 'string'],
            'code'        => ['required', 'string'],
            'verifier'    => ['required', 'string'],
        ]);

        try {
            $result = Iam::reauthentications()->redeem(
                $input['application'],
                $input['connection'],
                $input['code'],
                $input['verifier'],
                ClientContext::fromRequest($request),
            );
        } catch (ExternalReauthenticationRefusedException $refused) {
            // laravel-authentication refused the renewal; rolled back, so the code is unspent
            return response()->json(['reason' => $refused->result->reason?->value], 401);
        }

        if ($result instanceof RedemptionResult) {
            // SSO refused the code, and the refusal committed: the client starts again
            return response()->json(['reason' => $result->reason?->value], $result->isRateLimited() ? 429 : 400);
        }

        // The code renews the session it was started on: the caller is fresh only when that is theirs
        return $result->session?->getSessionIdentifier() === $caller->session?->getSessionIdentifier()
            ? response()->json(['status' => 'reauthenticated'])
            : response()->json(['status' => 'another_session_renewed'], 409);
    }
}
```

`redeem()` answers SSO's `RedemptionResult` for a refusal SSO committed, and an issued `AccessTokenResult` otherwise:
a renewal `laravel-authentication` refuses is never answered, but thrown as `ExternalReauthenticationRefusedException`
inside the transaction, so it rolls back with the code unspent
([Authentication and SSO](authentication-and-sso.md#re-authenticating)).

## Linking an identity

A link flow's start asks SSO's freshness, so the caller is handed in around it; the redemption takes the caller as a
value:

```php
namespace App\Http\Controllers;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Http\ClientContext as SsoClientContext;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

final class SsoLinkController
{
    public function __construct(private AuthorizationRequestService $requests) {}

    public function start(Request $request): JsonResponse
    {
        $caller = Auth::caller() ?? throw new AuthenticationException;

        $result = Iam::callers()->run($caller, fn (): StartResult => $this->requests->start(
            $caller->guard,
            Purpose::LINK,
            (string) $request->input('connection'),
            SsoClientContext::fromRequest($request),
            $request->input('code_challenge'),
            new IdentityReference($caller->identity->getMorphClass(), (string) $caller->identity->getKey()),
        ));

        return response()->json($result->body(), $result->isStarted() ? 200 : 400, $result->headers());
    }

    public function store(Request $request): JsonResponse
    {
        $caller = Auth::caller() ?? throw new AuthenticationException;

        $result = Iam::links()->redeem(
            (string) $request->input('connection'),
            (string) $request->input('code'),
            (string) $request->input('verifier'),
            ClientContext::fromRequest($request),
            $caller,
        );

        return $result->isRedeemed()
            ? response()->json(['link' => $result->linkId], 201, ['Cache-Control' => 'no-store'])
            : response()->json(['reason' => $result->reason?->value], 400);
    }
}
```

Note the two client contexts: SSO's own `Http\ClientContext` for SSO's start, and `laravel-authentication`'s for this
package's redemption. The start names the caller to SSO as the redemption does: by the identity model's morph class and
its primary key (`getKey()`), never its auth identifier, which a model may keep in another column; a flow started for
one id and redeemed for another is refused as SSO's `identity_mismatch`. A link is allowed only by an accepted
membership of the connection's tenant (see [Provisioning and tenancy](provisioning-and-tenancy.md#memberships)).

## Administering SSO

SSO's management helpers ask for a fresh session, so the caller is handed in around them; your authorisation decides
who may call them:

```php
namespace App\Http\Controllers;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Sso\Connections\ConnectionResult;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Http\ClientContext;

final class ConnectionController
{
    public function __construct(private ConnectionService $connections) {}

    public function enable(Request $request, string $connection): JsonResponse
    {
        $caller = Auth::caller() ?? throw new AuthenticationException;
        $tenant = (string) $caller->tenant?->getTenantIdentifier();

        $result = Iam::callers()->run($caller, fn (): ConnectionResult => $this->connections->enable(
            $tenant,
            $connection,
            ClientContext::fromRequest($request),
        ));

        return response()->json($result, $result->isSucceeded() ? 200 : 422);
    }
}
```

## Answering a step-up

MFA's gate raises `InsufficientAuthenticationException`. Answer it once, in `bootstrap/app.php`:

```php
use Illuminate\Foundation\Configuration\Exceptions;
use SineMacula\Laravel\Mfa\Exceptions\InsufficientAuthenticationException;

->withExceptions(function (Exceptions $exceptions): void {
    $exceptions->render(fn (InsufficientAuthenticationException $exception) => response()->json(
        $exception->toArray(),
        401,
        ['WWW-Authenticate' => $exception->wwwAuthenticate()],
    ));
})
```

`laravel-authorization` raises an exception of its own for an unmet `authentication_requirement`; this package does
not map it to MFA's yet, so render it too if your policies state one (see its [README][authorization-requirements]).

## A gateway

Every member's codes reach one gateway per channel as a `CodeMessage`, and the wording is yours:

```php
namespace App\Delivery;

use App\Mail\CodeMail;
use Illuminate\Support\Facades\Mail;
use SineMacula\Laravel\Iam\Contracts\EmailGateway;
use SineMacula\Laravel\Iam\Delivery\CodeMessage;

final readonly class MailCodes implements EmailGateway
{
    public function send(#[\SensitiveParameter] CodeMessage $message): void
    {
        // CodeMail is the application's own mailable, worded by the message's purpose
        Mail::to($message->destination())->send(new CodeMail($message->purpose, $message->code->reveal(), $message->expiresAt));
    }
}
```

Name it in `iam.delivery.email` (see [Authentication and MFA](authentication-and-mfa.md#codes-and-delivery)). Send it
once, never log the code or the address, and do not queue a mailable that holds the code: a gateway that queues its
delivery puts what it needs in a job whose whole payload is encrypted (`ShouldBeEncrypted`).

## Flows the members lay out

These flows need no core method of this package's: lay their routes out as the member's guide does, behind the same
middleware as the example's own (`auth:api`, then `mfa`), and mind what changes under this package.

| Flow                                  | Laid out in                                                                                           | Under this package                                                                                                                                                                                                                                                       |
|---------------------------------------|-------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Refreshing a session's tokens         | `laravel-authentication`'s [refreshing guide][auth-refreshing], behind `authentication.refresh`       | Nothing changes in the route.                                                                                                                                                                                                                                            |
| Signing out, and revoking sessions    | `laravel-authentication`'s [sessions guide][auth-signing-out]                                         | Nothing changes in the route; a person's own sign-out is recorded as `authentication.signed_out`.                                                                                                                                                                        |
| Enrolling a factor, and replacing one | MFA's [enrolment guide][mfa-enrollment], a bootstrap enrolment exempt from the gate with `mfa.exempt` | Takes `mfa.add_factor` or `mfa.replace_factor` freshness, declared for the guard; an identity's first additional factor takes a fresh reauthentication instead. Without an enrolment route a person who signs in with a password never meets a tenant's MFA requirement. |
| Removing a factor                     | MFA's [lifecycle guide][mfa-removing]                                                                 | Takes `mfa.remove_factor` freshness. The package's adapters end the identity's other sessions and return a session left short to pending; the removal's `completion()` carries its new pending credential back to the client.                                            |
| Generating recovery codes             | MFA's [recovery codes guide][mfa-recovery-codes], behind `mfa.no-store`                               | Takes `mfa.generate_recovery_codes` freshness.                                                                                                                                                                                                                           |

Declare each freshness operation for the guard (see [Installation](installation.md#guards-and-applications)), or
`iam:check` refuses it. Each of MFA's changes opens its own transaction, and this package's adapters run inside it, so
call MFA from the controller directly: never inside `Iam::transaction()` or a transaction of your own, and when one
fails to serialise or deadlocks, retry the request (see
[Transactions and retries](authentication-and-mfa.md#transactions-and-retries)).

## What the example leaves to you

- **Your models and contracts.** The identity, principal and tenant models, your memberships, tenant tree, tenant MFA
  requirement and provisioner (see [Provisioning and tenancy](provisioning-and-tenancy.md)).
- **Your authorisation.** Who may administer a tenant's SSO, refund an invoice or act in a tenant, and
  `laravel-authentication`'s tenant access (see [Authorization](authorization.md#access-contracts)).
  `laravel-authorization` decides in the caller's tenant but refuses no resource for its tenant, so have your models
  name their tenant, bind your own resource tenant resolver, or scope each route-bound model to the caller's tenant
  (see [Authorization](authorization.md#tenants)).
- **Cross-site request forgery.** Every route above takes its credential from a header or the body. If yours
  authenticate by cookie, put them under Laravel's CSRF protection (see MFA's [middleware guide][mfa-csrf]) and exempt
  only SSO's assertion consumer service.
- **Your throttles.** The members limit sign-ins, codes, verifications and redemptions; add your own limits as you would
  to any route.

[sso-example]: https://github.com/sinemacula/laravel-sso/blob/master/docs/guides/example-application.md
[auth-signing-in]: https://github.com/sinemacula/laravel-authentication/blob/master/docs/guides/signing-in.md
[authorization-requirements]: https://github.com/sinemacula/laravel-authorization/blob/master/README.md#the-decision-and-the-exception
[auth-refreshing]: https://github.com/sinemacula/laravel-authentication/blob/master/docs/guides/refreshing.md
[auth-signing-out]: https://github.com/sinemacula/laravel-authentication/blob/master/docs/guides/sessions.md#signing-out-and-revoking-sessions
[mfa-enrollment]: https://github.com/sinemacula/laravel-mfa/blob/master/docs/guides/enrollment.md
[mfa-removing]: https://github.com/sinemacula/laravel-mfa/blob/master/docs/guides/lifecycle.md#removing-a-factor
[mfa-recovery-codes]: https://github.com/sinemacula/laravel-mfa/blob/master/docs/guides/recovery-codes.md
[mfa-csrf]: https://github.com/sinemacula/laravel-mfa/blob/master/docs/guides/middleware.md#csrf-protection
