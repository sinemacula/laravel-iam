<?php

declare(strict_types = 1);

namespace Tests\Integration\EndToEnd;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Foundation\Exceptions\Handler;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding;
use SineMacula\Laravel\Authentication\Proofs\ProofResult;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Iam\Mfa\ProofStoreAdapter;
use SineMacula\Laravel\Iam\Mfa\SessionRevokerAdapter;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Exceptions\InsufficientAuthenticationException as StepUp;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Concerns\MigratesAuthorization;
use Tests\Fixtures\Authorization\Enums\InvoicePermission;
use Tests\Fixtures\Authorization\Member;
use Tests\TestCase;

/**
 * End-to-end tests that a step-up carries over a token refresh, until the
 * factor that made it is removed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProofStoreAdapter::class)]
#[CoversClass(SessionRevokerAdapter::class)]
final class StepUpRefreshTest extends TestCase
{
    use MigratesAuthorization;

    /** @var string The action a policy allows only after a step-up. */
    private const string REFUND = 'invoices:refund';

    /**
     * Render MFA's step-up exception as its RFC 9470 challenge.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $handler = $this->app?->make(ExceptionHandler::class);

        assert($handler instanceof Handler);

        $handler->renderable(static fn (StepUp $exception): JsonResponse => new JsonResponse($exception->toArray(), 401, ['WWW-Authenticate' => $exception->wwwAuthenticate()]));
    }

    /**
     * A refreshed token keeps the step-up until its factor is removed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshedTokenKeepsTheStepUpUntilItsFactorIsRemoved(): void
    {
        $member   = $this->member();
        $signedIn = $this->signIn($member);
        $factor   = $this->confirmedFactor($member);
        $token    = $signedIn->tokens->accessToken->reveal();

        $this->request('GET', '/aal2', $token)->assertUnauthorized()->assertJsonPath('error', StepUp::ERROR);

        $this->request('POST', '/verify', $token, ['factor' => $factor->getKey(), 'code' => AuthenticatorApp::code($factor)])
            ->assertOk()
            ->assertExactJson(['verified' => true]);

        $refreshed = $this->refresh($signedIn);

        self::assertNotSame($token, $refreshed);

        $this->request('GET', '/aal2', $refreshed)->assertOk()->assertExactJson(['reached' => true]);
        $this->request('POST', '/refund', $refreshed)->assertOk()->assertExactJson(['refunded' => true]);

        // A factor never authorises its own removal, so step up with another.
        $this->stepUpWithAnEmailCode($member, $signedIn);

        $this->request('GET', '/aal2', $refreshed)->assertOk();
        $this->request('POST', '/remove', $refreshed, ['factor' => $factor->getKey()])->assertOk()->assertExactJson(['refusal' => null]);

        $this->request('GET', '/aal2', $refreshed)->assertUnauthorized()->assertJsonPath('error', StepUp::ERROR);
        $this->request('POST', '/refund', $refreshed)->assertUnauthorized()->assertJsonPath('error', StepUp::ERROR);
    }

    /**
     * Define the routes on the stateless guard, with no session middleware.
     *
     * @param  mixed  $router
     * @return void
     */
    #[\Override]
    protected function defineRoutes(mixed $router): void
    {
        assert($router instanceof Router);

        $router->post('verify', static function (Request $request): JsonResponse {

            $result = Mfa::verify(CallerContext::fromRequest($request), Submission::factor($request->string('factor')->toString(), $request->string('code')->toString()));

            return new JsonResponse(['verified' => $result->isVerified()]);
        })->middleware('auth:' . self::GUARD);

        $router->post('remove', static fn (Request $request): JsonResponse => new JsonResponse([
            'refusal' => Mfa::removeFactor(CallerContext::fromRequest($request), $request->string('factor')->toString())->reason?->value,
        ]))->middleware('auth:' . self::GUARD);

        $router->get('aal2', static fn (): JsonResponse => new JsonResponse(['reached' => true]))
            ->middleware(['auth:' . self::GUARD, 'mfa:level=aal2']);

        $router->post('refund', static function (): JsonResponse {

            Authorization::authorize(self::REFUND);

            return new JsonResponse(['refunded' => true]);
        })->middleware('auth:' . self::GUARD);
    }

    /**
     * Sign members in, require no factor of the identity, and declare the
     * invoice permissions, set before any provider registers.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function resolveApplicationConfiguration(mixed $app): void
    {
        parent::resolveApplicationConfiguration($app);

        $config = $app->make('config');

        $config->set('auth.providers.people', ['driver' => 'model', 'model' => Member::class]);
        $config->set('authorization.permission_enums', [InvoicePermission::class]);
        $config->set('mfa.applications.' . self::GUARD . '.requirement', 'never');
    }

    /**
     * A member whose only grant allows a refund once its session is
     * multifactor.
     *
     * @return \Tests\Fixtures\Authorization\Member
     */
    private function member(): Member
    {
        $member = Member::query()->create(['name' => 'Ada Lovelace', 'email' => 'ada@example.test', 'password' => self::PASSWORD]);

        $member->attachPolicy(Policy::query()->create([
            'name'     => 'refunds-after-step-up',
            'document' => [
                'statements' => [
                    [
                        'sid'        => 'refund-after-step-up',
                        'effect'     => 'allow',
                        'actions'    => [self::REFUND],
                        'conditions' => ['authentication_requirement' => ['authentication' => ['multifactor' => []]]],
                    ],
                ],
            ],
        ]));

        return $member;
    }

    /**
     * Sign the member in with their password.
     *
     * @param  \Tests\Fixtures\Authorization\Member  $member
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signIn(Member $member): SignedInSession
    {
        $result = $this->auth()->sessions(self::GUARD)->signIn('password', ['email' => $member->email, 'password' => self::PASSWORD], new SignInContext(self::client()));

        self::assertTrue($result->isSignedIn(), (string) $result->reason?->value);

        return $result->session ?? self::fail('The sign-in established no session.');
    }

    /**
     * Refresh the session with its refresh token, answering the new access
     * token.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $signedIn
     * @return string
     *
     * @throws \Throwable
     */
    private function refresh(SignedInSession $signedIn): string
    {
        $presented = PresentedRefreshToken::fromBody($signedIn->tokens->refreshToken ?? self::fail('The session has no refresh token.'));
        $result    = $this->auth()->sessions(self::GUARD)->refresh($presented, self::client());

        self::assertTrue($result?->isRefreshed() ?? false, (string) $result?->reason?->value);

        return $result?->session?->tokens->accessToken->reveal() ?? self::fail('The refresh issued no access token.');
    }

    /**
     * Step the session up with an email code, which is no multifactor proof.
     *
     * @param  \Tests\Fixtures\Authorization\Member  $member
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $signedIn
     * @return void
     *
     * @throws \Throwable
     */
    private function stepUpWithAnEmailCode(Member $member, SignedInSession $signedIn): void
    {
        $result = $this->auth()->sessions(self::GUARD)->stepUp(new ProofResult(
            ProofKind::ADDITIONAL_FACTOR,
            'email',
            new Channel(ChannelKind::EMAIL, 'email-code'),
            'email-code',
            new ObservedProperties(userPresence: true),
            new Evaluation(true, false),
            ['otp'],
            CarbonImmutable::now(),
            new ProofBinding($member, self::GUARD, $signedIn->record->getSessionIdentifier(), Purpose::STEP_UP),
        ), self::client());

        self::assertTrue($result->isIssued(), (string) $result->reason?->value);
    }

    /**
     * A confirmed authenticator app factor on the guard's application.
     *
     * @param  \Tests\Fixtures\Authorization\Member  $member
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function confirmedFactor(Member $member): Factor
    {
        return Factor::query()->create([
            ...AuthenticatorApp::FACTOR,
            'authenticatable_type' => $member->getMorphClass(),
            'authenticatable_id'   => ProofOwner::of($member)->key,
            'status'               => 'confirmed',
            'confirmed_at'         => CarbonImmutable::now(),
            'application'          => self::GUARD,
        ]);
    }

    /**
     * Make a fresh request with the bearer token.
     *
     * @param  string  $method
     * @param  string  $uri
     * @param  string  $token
     * @param  array<string, mixed>  $data
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     *
     * @throws \Throwable
     */
    private function request(string $method, string $uri, string $token, array $data = []): TestResponse
    {
        $this->auth()->forgetGuardState();

        return $this->withToken($token)->json($method, $uri, $data);
    }

    /**
     * `laravel-authentication`'s manager.
     *
     * @return \SineMacula\Laravel\Authentication\AuthManager
     */
    private function auth(): AuthManager
    {
        $auth = $this->app?->make('auth');

        self::assertInstanceOf(AuthManager::class, $auth);

        return $auth;
    }

    /**
     * The client the tests sign in from.
     *
     * @return \SineMacula\Laravel\Authentication\Http\ClientContext
     */
    private static function client(): ClientContext
    {
        return new ClientContext('192.0.2.10', 'iam-tests');
    }
}
