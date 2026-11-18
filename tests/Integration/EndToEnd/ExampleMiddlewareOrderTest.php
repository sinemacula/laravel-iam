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
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Secrets\SecretResponse;
use SineMacula\Laravel\Authentication\Sessions\AccessTokenResult;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Exceptions\InsufficientAuthenticationException as StepUp;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Concerns\MigratesAuthorization;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Fixtures\Authorization\Enums\InvoicePermission;
use Tests\Fixtures\Authorization\Member;
use Tests\TestCase;

/**
 * End-to-end tests of the example application's middleware order: `auth:api`,
 * then MFA's gate, then `laravel-authorization`'s, so a weak session is asked
 * to step up before it can be denied, with every adapter of this package's
 * bound.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class ExampleMiddlewareOrderTest extends TestCase
{
    use MigratesAuthorization, RunsAtIsolationLevels;

    /** @var string The action a refund is. */
    private const string REFUND = 'invoices:refund';

    /** @var string The path the caller steps up on. */
    private const string STEP_UP = '/api/mfa/verifications';

    /**
     * Render MFA's step-up exception as the example's `bootstrap/app.php`
     * does.
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

        self::assertInstanceOf(Handler::class, $handler);

        $handler->renderable(static fn (StepUp $exception): JsonResponse => new JsonResponse($exception->toArray(), 401, ['WWW-Authenticate' => $exception->wwwAuthenticate()]));
    }

    /**
     * Rows of `[isolation level, path, application requirement]` for the
     * refund behind `authorize:` and behind `permission:`, with MFA's gate
     * asking for the enrolled factors or only the route's own level.
     *
     * @return iterable<string, array{0: ?string, 1: string, 2: string}>
     */
    public static function provideRefundRoutes(): iterable
    {
        foreach (self::provideEveryIsolationLevel() as $name => [$level]) {
            foreach (['enrolled', 'never'] as $requirement) {
                yield $name . ', authorize, ' . $requirement => [$level, '/api/invoices/inv-1/refund', $requirement];

                yield $name . ', permission, ' . $requirement => [$level, '/api/refunds', $requirement];
            }
        }
    }

    /**
     * A password-only token is asked to step up on the refund whether or not it
     * holds the permission, reaches the exempt step-up route, and once stepped
     * up is refunded or denied by its grants.
     *
     * @param  ?string  $level
     * @param  string  $path
     * @param  string  $requirement
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideRefundRoutes')]
    public function testAWeakSessionStepsUpBeforeItIsAuthorized(?string $level, string $path, string $requirement): void
    {
        self::runAtIsolationLevel($level);

        config()->set('mfa.applications.' . self::GUARD . '.requirement', $requirement);

        $permitted   = $this->member('ada@example.test', true);
        $unpermitted = $this->member('grace@example.test', false);

        $tokens = [];

        foreach (['permitted' => $permitted, 'unpermitted' => $unpermitted] as $name => $member) {

            $token  = $this->signIn($member);
            $factor = $this->confirmedFactor($member);
            $denied = $this->request($path, $token);

            $denied->assertUnauthorized()->assertJsonPath('error', StepUp::ERROR)->assertJsonPath('has_confirmed_factor', true);

            self::assertStringContainsString('insufficient_user_authentication', (string) $denied->headers->get('WWW-Authenticate'), $name);

            $stepUp = $this->request(self::STEP_UP, $token, ['factor' => $factor->getKey(), 'code' => AuthenticatorApp::code($factor)]);

            $tokens[$name] = (string) $stepUp->assertOk()->json('access_token');
        }

        $this->request($path, $tokens['permitted'])->assertOk()->assertExactJson(['refunded' => true]);
        $this->request($path, $tokens['unpermitted'])->assertForbidden();
    }

    /**
     * Lay out the example application's step-up and refund routes, and the
     * refund behind `permission:` as well, with no session middleware.
     *
     * @param  mixed  $router
     * @return void
     */
    #[\Override]
    protected function defineRoutes(mixed $router): void
    {
        assert($router instanceof Router);

        $router->middleware(['auth:api', 'mfa'])->group(static function (Router $router): void {

            $router->post('api/mfa/verifications', static function (Request $request): JsonResponse {

                $submission = Submission::factor($request->string('factor')->toString(), $request->string('code')->toString());
                $result     = Mfa::verify(CallerContext::fromRequest($request, 'api'), $submission);
                $token      = $result->completion();

                return $token instanceof AccessTokenResult && $token->isIssued()
                    ? SecretResponse::json(['access_token' => $token->accessToken, 'expires_at' => $token->expiresAt])
                    : new JsonResponse(['reason' => $result->reason?->value], 422);
            })->middleware('mfa.exempt');

            $refunded = static fn (): JsonResponse => new JsonResponse(['refunded' => true]);

            $router->post('api/invoices/{invoice}/refund', $refunded)->middleware(['mfa:level=aal2', 'authorize:' . self::REFUND . ',invoice']);
            $router->post('api/refunds', $refunded)->middleware(['mfa:level=aal2', 'permission:' . self::REFUND]);
        });
    }

    /**
     * Load the application's configuration, then sign members in on the guard
     * people sign in on, and declare the invoice permissions, set before any
     * provider registers.
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
    }

    /**
     * A member, granted the refund outright when permitted and nothing
     * otherwise.
     *
     * @param  string  $email
     * @param  bool  $permitted
     * @return \Tests\Fixtures\Authorization\Member
     */
    private function member(string $email, bool $permitted): Member
    {
        $member = Member::query()->create(['name' => 'Ada Lovelace', 'email' => $email, 'password' => self::PASSWORD]);

        if ($permitted) {
            $member->attachPolicy(Policy::query()->create([
                'name'     => 'refunds',
                'document' => ['statements' => [['sid' => 'refund', 'effect' => 'allow', 'actions' => [self::REFUND]]]],
            ]));
        }

        return $member;
    }

    /**
     * Sign the member in with their password and return the session's access
     * token.
     *
     * @param  \Tests\Fixtures\Authorization\Member  $member
     * @return string
     *
     * @throws \Throwable
     */
    private function signIn(Member $member): string
    {
        $auth = $this->app?->make('auth');

        self::assertInstanceOf(AuthManager::class, $auth);

        $result = $auth->sessions(self::GUARD)->signIn('password', ['email' => $member->email, 'password' => self::PASSWORD], new SignInContext(new ClientContext('192.0.2.10', 'iam-tests')));

        self::assertTrue($result->isSignedIn());
        self::assertNotNull($result->session);

        return $result->session->tokens->accessToken->reveal();
    }

    /**
     * A confirmed authenticator app factor of the member's on the guard's
     * application.
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
     * Make a JSON request as a new one, with the bearer token and nothing the
     * previous request bound.
     *
     * @param  string  $uri
     * @param  string  $token
     * @param  array<string, mixed>  $data
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     *
     * @throws \Throwable
     */
    private function request(string $uri, #[\SensitiveParameter] string $token, array $data = []): TestResponse
    {
        $auth = $this->app?->make('auth');

        self::assertInstanceOf(AuthManager::class, $auth);

        $auth->forgetGuardState();

        return $this->withToken($token)->postJson($uri, $data);
    }
}
