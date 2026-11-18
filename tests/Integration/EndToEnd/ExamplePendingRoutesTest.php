<?php

declare(strict_types = 1);

namespace Tests\Integration\EndToEnd;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Secrets\SecretResponse;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\PendingCompletionAdapter;
use SineMacula\Laravel\Iam\Mfa\PendingSessionResolverAdapter;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Mfa\Codes\Concerns\ArrangesDeliveredFactors;
use Tests\Fixtures\Mfa\Codes\Concerns\DeliversFactorCodes;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * End-to-end tests of the example application's pending routes, laid out as
 * its guide lays them out, with every adapter of this package's bound.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PendingSessionResolverAdapter::class)]
#[CoversClass(PendingCompletionAdapter::class)]
final class ExamplePendingRoutesTest extends TestCase
{
    use ArrangesDeliveredFactors, DeliversFactorCodes, MigratesMembers, RunsAtIsolationLevels, SignsInPeople;

    /** @var string The path a code is sent to a pending sign-in's factor on. */
    private const string CODES = '/api/auth/sessions/pending/codes';

    /** @var string The path a pending sign-in verifies its factor on. */
    private const string VERIFICATIONS = '/api/auth/sessions/pending/verifications';

    /** @var string A path only an active session reaches. */
    private const string PROFILE = '/api/profile';

    /**
     * Queue the deliveries, so each code reaches the fake sender once its job
     * runs.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->fakeFactorCodeDelivery();
    }

    /**
     * A password sign-in waits pending, sends a code and verifies it over the
     * pending routes, and the access token it is issued reaches the caller's
     * own routes.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAPendingSignInCompletesOverThePendingRoutes(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person     = $this->createPerson();
        $factor     = $this->deliveredFactor($person, 'email');
        $credential = $this->signInPending($person);

        $verified = $this->complete($credential, (string) $factor->id, $person->email);

        $verified->assertHeader('Cache-Control', 'no-store, private');

        $token = (string) $verified->json('access_token');

        $this->send(self::PROFILE, [], $token)->assertOk()->assertExactJson(['id' => $person->getKey()]);
    }

    /**
     * The pending credential never reaches the caller's own routes, as a bearer
     * token or in the body, before the sign-in completes or after.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testThePendingCredentialNeverReachesTheCallersRoutes(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person     = $this->createPerson();
        $factor     = $this->deliveredFactor($person, 'email');
        $credential = $this->signInPending($person);

        $this->send(self::PROFILE, [], $credential)->assertUnauthorized();
        $this->send(self::PROFILE, ['pending_credential' => $credential])->assertUnauthorized();

        $this->complete($credential, (string) $factor->id, $person->email);

        $this->send(self::PROFILE, [], $credential)->assertUnauthorized();
        $this->send(self::PROFILE, ['pending_credential' => $credential])->assertUnauthorized();
    }

    /**
     * Once the sign-in completes its pending credential names no live pending
     * session, so the pending routes refuse it rather than serve anyone, and no
     * further code is sent.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testACompletedPendingCredentialIsRefusedOnThePendingRoutes(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person     = $this->createPerson();
        $factor     = $this->deliveredFactor($person, 'email');
        $credential = $this->signInPending($person);

        $this->complete($credential, (string) $factor->id, $person->email);

        $sent = $this->send(self::CODES, ['pending_credential' => $credential, 'factor' => $factor->id]);

        $sent->assertServerError();
        self::assertInstanceOf(UnresolvedReferenceException::class, $sent->exception);
        self::assertSame(0, $this->queuedDeliveries());

        $verified = $this->send(self::VERIFICATIONS, ['pending_credential' => $credential, 'factor' => $factor->id, 'challenge' => 'any', 'code' => '000000']);

        $verified->assertServerError();
        self::assertInstanceOf(UnresolvedReferenceException::class, $verified->exception);
    }

    /**
     * Lay out the example application's sign-in, its two pending routes and a
     * route of the caller's own, with no session middleware.
     *
     * @param  mixed  $router
     * @return void
     */
    #[\Override]
    protected function defineRoutes(mixed $router): void
    {
        assert($router instanceof Router);

        $router->post('api/auth/sessions', static function (Request $request): JsonResponse {

            $result = Auth::sessions('api')->signIn('password', $request->only('email', 'password'), SignInContext::fromRequest($request));

            abort_if($result->isFailed(), 401);

            return $result->isPending()
                ? SecretResponse::json(['status' => 'pending', 'pending_credential' => $result->credential])
                : SecretResponse::json(['access_token' => $result->session?->tokens->accessToken]);
        });

        $router->post('api/auth/sessions/pending/codes', static function (Request $request): JsonResponse {

            $sent = Mfa::sendCode(CallerContext::fromRequest($request, 'api'), $request->input('factor'));

            return $sent->wasSent()
                ? new JsonResponse(['challenge' => $sent->challengeId, 'expires_at' => $sent->expiresAt])
                : new JsonResponse(['reason' => $sent->reason?->value], 422);
        })->middleware('authentication.pending:mfa.send_code,api');

        $router->post('api/auth/sessions/pending/verifications', static function (Request $request): JsonResponse {

            $submission = Submission::challenge($request->string('factor')->toString(), $request->string('challenge')->toString(), $request->string('code')->toString());
            $result     = Mfa::verify(CallerContext::fromRequest($request, 'api'), $submission);
            $signIn     = $result->completion();

            if ($result->isFailed() || !$signIn instanceof SignInResult || !$signIn->isSignedIn()) {
                return new JsonResponse(['reason' => $result->reason?->value], 422);
            }

            return SecretResponse::json(['access_token' => $signIn->session?->tokens->accessToken]);
        })->middleware('authentication.pending:mfa.verify,api');

        $router->post('api/profile', static fn (Request $request): JsonResponse => new JsonResponse(['id' => $request->user()?->getAuthIdentifier()]))
            ->middleware(['auth:api', 'mfa']);
    }

    /**
     * Bind the fake one-time code sender before the application boots.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $this->defineFactorCodes($app);
    }

    /**
     * Sign the person in over the sign-in route and return the pending
     * credential it answers.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return string
     *
     * @throws \Throwable
     */
    private function signInPending(Person $person): string
    {
        $signIn = $this->send('/api/auth/sessions', ['email' => $person->email, 'password' => self::PASSWORD]);

        $signIn->assertOk()->assertJsonPath('status', 'pending')->assertJsonMissingPath('access_token');

        return (string) $signIn->json('pending_credential');
    }

    /**
     * Complete the pending sign-in over the pending routes with the factor's
     * code, and return the verification's response.
     *
     * @param  string  $credential
     * @param  string  $factor
     * @param  string  $destination
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     *
     * @throws \Throwable
     */
    private function complete(#[\SensitiveParameter] string $credential, string $factor, string $destination): TestResponse
    {
        $sent = $this->send(self::CODES, ['pending_credential' => $credential, 'factor' => $factor]);

        $sent->assertOk();

        return $this->send(self::VERIFICATIONS, [
            'pending_credential' => $credential,
            'factor'             => $factor,
            'challenge'          => (string) $sent->json('challenge'),
            'code'               => $this->deliveredCodeTo($destination),
        ])->assertOk();
    }

    /**
     * Make a JSON request as a new one, with the bearer token when one is
     * given, and nothing the previous request bound.
     *
     * @param  string  $uri
     * @param  array<string, mixed>  $data
     * @param  ?string  $token
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     *
     * @throws \Throwable
     */
    private function send(string $uri, array $data = [], #[\SensitiveParameter] ?string $token = null): TestResponse
    {
        $auth = $this->app?->make('auth');

        self::assertInstanceOf(AuthManager::class, $auth);

        $auth->forgetGuardState();

        $this->flushHeaders();

        return $token === null ? $this->postJson($uri, $data) : $this->withToken($token)->postJson($uri, $data);
    }
}
