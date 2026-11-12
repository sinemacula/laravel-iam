<?php

declare(strict_types = 1);

namespace Tests\Integration\Authorization;

use Carbon\CarbonImmutable;
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
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Enums\Purpose;
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
 * End-to-end tests for forgetting decisions when authentication changes.
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
     * Removing a factor forgets the allow that read its proof.
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
     * Passing a step-up forgets the refusal that read the earlier proofs.
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
     * Define routes that check, change through MFA, and check again.
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
     * Sign members in on the people guard and declare the permissions.
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
     * Step the caller up through MFA, answering whether it verified.
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
     * Check, change, then report the decisions before and after.
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
     * A member allowed a refund only after a recent multifactor step-up.
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
     * Sign the member in and return the access token.
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
     * A confirmed authenticator app factor of the member's.
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
        $auth = $this->app?->make('auth');

        self::assertInstanceOf(AuthManager::class, $auth);

        $auth->forgetGuardState();

        return $this->withToken($token)->json($method, $uri, $data);
    }
}
