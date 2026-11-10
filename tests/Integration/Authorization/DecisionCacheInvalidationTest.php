<?php

declare(strict_types = 1);

namespace Tests\Integration\Authorization;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Iam\Authorization\DecisionCacheInvalidation;
use SineMacula\Laravel\Iam\Mfa\SessionRevokerAdapter;
use SineMacula\Laravel\Iam\Mfa\StepUpAdapter;
use SineMacula\Laravel\Iam\Mfa\Translation\IdentityReference;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Concerns\MigratesAuthorization;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Fixtures\Authorization\Enums\InvoicePermission;
use Tests\Fixtures\Authorization\Member;
use Tests\TestCase;

/**
 * End-to-end tests of forgetting the decision `laravel-authorization` keeps
 * once the authentication it read changes (IAM-6.11), with every adapter of
 * this package's bound: a member allowed a refund through a recent multifactor
 * requirement, its session stepped up with one authenticator app and, later,
 * another, removes the later one through MFA in the same request, and the allow
 * is no longer the last decision, while the next check is refused; and a member
 * refused for want of a step-up steps up through MFA in the same request, and
 * the refusal is no longer the last decision, while the next check allows.
 *
 * `laravel-authorization` decides every check afresh, so the next check reads
 * the session's proofs as they are either way; the decision it keeps is the
 * request's last, which an application's error handler reads to explain a
 * refusal, and which would otherwise outlive the proofs it read until its
 * requirement lapsed. Everything runs on every engine, and at READ COMMITTED
 * and REPEATABLE READ on MySQL and PostgreSQL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DecisionCacheInvalidation::class)]
#[CoversClass(SessionRevokerAdapter::class)]
#[CoversClass(StepUpAdapter::class)]
final class DecisionCacheInvalidationTest extends TestCase
{
    use MigratesAuthorization, RunsAtIsolationLevels;

    /** @var string The action a refund is. */
    private const string REFUND = 'invoices:refund';

    /** @var int How recent the multifactor authentication a refund requires must be, in seconds. */
    private const int MAX_AGE = 120;

    /**
     * A factor removed in the request that checked the refund leaves no allow
     * behind that read the proofs it made, and the next check is refused: the
     * session's step-up with the factor kept, which MFA's freshness takes for
     * the removal, is too old for the refund.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAFactorRemovedForgetsTheAllowThatReadItsProof(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $member  = $this->member();
        $token   = $this->signIn($member);
        $kept    = $this->confirmedFactor($member);
        $removed = $this->confirmedFactor($member);

        $this->request('POST', '/verify', $token, ['factor' => $kept->getKey(), 'code' => AuthenticatorApp::code($kept)])->assertOk()->assertExactJson(['verified' => true]);

        $this->travel(self::MAX_AGE + 60)->seconds();

        $this->request('POST', '/verify', $token, ['factor' => $removed->getKey(), 'code' => AuthenticatorApp::code($removed)])->assertOk()->assertExactJson(['verified' => true]);

        $this->request('POST', '/remove', $token, ['factor' => $removed->getKey()])
            ->assertOk()
            ->assertExactJson(['before' => true, 'kept' => true, 'changed' => true, 'last' => null, 'after' => false]);
    }

    /**
     * A step-up through MFA in the request refused for want of one leaves no
     * refusal behind that read the proofs before it, and the next check allows.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAVerificationPassedForgetsTheRefusalThatReadTheProofsBeforeIt(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $member = $this->member();
        $token  = $this->signIn($member);
        $factor = $this->confirmedFactor($member);

        $this->request('POST', '/step-up', $token, ['factor' => $factor->getKey(), 'code' => AuthenticatorApp::code($factor)])
            ->assertOk()
            ->assertExactJson(['before' => false, 'kept' => true, 'changed' => true, 'last' => null, 'after' => true]);
    }

    /**
     * Define the routes the requests are made to, on the stateless guard: each
     * checks the refund, makes the change through MFA, then reads the last
     * decision and checks again.
     *
     * @param  mixed  $router
     * @return void
     */
    #[\Override]
    protected function defineRoutes(mixed $router): void
    {
        assert($router instanceof Router);

        $router->post('verify', static fn (Request $request): JsonResponse => new JsonResponse(['verified' => self::isSteppedUp($request)]))
            ->middleware('auth:' . self::GUARD);

        $router->post('remove', static fn (Request $request): JsonResponse => self::checkAround(
            static fn (): bool => Mfa::removeFactor(CallerContext::fromRequest($request), $request->string('factor')->toString())->wasMade(),
        ))->middleware('auth:' . self::GUARD);

        $router->post('step-up', static fn (Request $request): JsonResponse => self::checkAround(static fn (): bool => self::isSteppedUp($request)))
            ->middleware('auth:' . self::GUARD);
    }

    /**
     * Load the application's configuration, then sign members in on the guard
     * people sign in on, and declare the invoice permissions, set before any
     * provider registers.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function resolveApplicationConfiguration(mixed $app): void
    {
        parent::resolveApplicationConfiguration($app);

        assert($app instanceof Application);

        $config = $app->make('config');

        $config->set('auth.providers.people', ['driver' => 'model', 'model' => Member::class]);
        $config->set('authorization.permission_enums', [InvoicePermission::class]);
    }

    /**
     * Step the request's caller up through MFA with the factor and code it
     * sends, answering whether MFA verified it.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return bool
     */
    private static function isSteppedUp(Request $request): bool
    {
        $submission = Submission::factor($request->string('factor')->toString(), $request->string('code')->toString());

        return Mfa::verify(CallerContext::fromRequest($request), $submission, Purpose::STEP_UP)->isVerified();
    }

    /**
     * Check the refund, make the change, then answer whether the last decision
     * was the check's before the change, the change made, the last decision's
     * effect after it, and the refund checked again.
     *
     * @param  \Closure(): bool  $change
     * @return \Illuminate\Http\JsonResponse
     */
    private static function checkAround(\Closure $change): JsonResponse
    {
        $before = Authorization::can(self::REFUND);
        $kept   = Authorization::lastDecision() !== null;

        $changed = $change();

        return new JsonResponse([
            'before'  => $before,
            'kept'    => $kept,
            'changed' => $changed,
            'last'    => Authorization::lastDecision()?->effect->value,
            'after'   => Authorization::can(self::REFUND),
        ]);
    }

    /**
     * A member whose only grant is a policy allowing a refund while its session
     * was made multifactor within `MAX_AGE`.
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
                        'conditions' => ['authentication_requirement' => ['authentication' => ['multifactor' => ['max_age' => self::MAX_AGE]]]],
                    ],
                ],
            ],
        ]));

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

        $client = new SignInContext(new ClientContext('192.0.2.10', 'iam-tests'));
        $result = $auth->sessions(self::GUARD)->signIn('password', ['email' => $member->email, 'password' => self::PASSWORD], $client);

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
            'authenticatable_id'   => IdentityReference::of($member)->key,
            'status'               => 'confirmed',
            'confirmed_at'         => CarbonImmutable::now(),
            'application'          => self::GUARD,
        ]);
    }

    /**
     * Make a request as a new one, with the bearer token and nothing the
     * previous request bound.
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
        $auth = $this->app?->make('auth');

        self::assertInstanceOf(AuthManager::class, $auth);

        $auth->forgetGuardState();

        return $this->withToken($token)->json($method, $uri, $data);
    }
}
