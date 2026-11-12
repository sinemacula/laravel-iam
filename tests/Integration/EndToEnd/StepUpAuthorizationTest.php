<?php

declare(strict_types = 1);

namespace Tests\Integration\EndToEnd;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Foundation\Exceptions\Handler;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Gate;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Iam\Authorization\AuthenticationContextAdapter;
use SineMacula\Laravel\Iam\Authorization\InsufficientAuthenticationMapping;
use SineMacula\Laravel\Iam\Authorization\RequirementCheckerAdapter;
use SineMacula\Laravel\Iam\Authorization\SubjectResolverAdapter;
use SineMacula\Laravel\Iam\Mfa\Translation\CodeTranslator;
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
use Tests\Fixtures\Authorization\Organisation;
use Tests\Fixtures\Authorization\OrganisationTenancy;
use Tests\TestCase;

/**
 * End-to-end tests of a policy statement that states an authentication
 * requirement (IAM-6.1 to IAM-6.4), with every adapter of this package's bound:
 * a member whose only grant is an allow requiring multifactor authentication is
 * refused with MFA's step-up until the session steps up through MFA, on one
 * request with its bearer token, and allowed on the next with the same token,
 * through `laravel-authorization`'s manager and Laravel's Gate alike; a member
 * acting in a tenant is listed the action (`permissionsFor()`) in its own scope
 * exactly when the check allows it; the member's other session, never stepped
 * up, is still refused; a refusal about a member the caller names, which holds
 * no session, is Laravel's 403, since no step-up by the caller could meet it; a
 * member with no confirmed factor is told so and offered none; and a
 * requirement naming a level MFA does not know cannot be judged, so its allow
 * never applies and the refusal is Laravel's 403, not a step-up.
 *
 * The step-up is a real one: an authenticator app code verified through
 * `Mfa::verify()` on a stateless guard, which `laravel-authentication` records
 * on the token's session, and the requirement checker reads back from that
 * session alone. The application renders MFA's step-up exception as its RFC
 * 9470 challenge, and nothing more: this package turns
 * `laravel-authorization`'s refusal into it. Everything runs on every engine,
 * and at READ COMMITTED and REPEATABLE READ on MySQL and PostgreSQL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SubjectResolverAdapter::class)]
#[CoversClass(AuthenticationContextAdapter::class)]
#[CoversClass(RequirementCheckerAdapter::class)]
#[CoversClass(InsufficientAuthenticationMapping::class)]
final class StepUpAuthorizationTest extends TestCase
{
    use MigratesAuthorization, RunsAtIsolationLevels;

    /** @var string The action a refund is. */
    private const string REFUND = 'invoices:refund';

    /** @var string The action a policy requires a level MFA does not know for. */
    private const string VOID = 'invoices:void';

    /** @var string The tenant a member acting in one signed in to. */
    private const string TENANT = 'org-7';

    /**
     * Render MFA's step-up exception as the application's own handler would:
     * its RFC 9470 challenge, with `toArray()` as the body.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $handler = $this->resolved(ExceptionHandler::class);

        assert($handler instanceof Handler);

        $handler->renderable(static fn (StepUp $exception): JsonResponse => new JsonResponse($exception->toArray(), 401, ['WWW-Authenticate' => $exception->wwwAuthenticate()]));
    }

    /**
     * A member is refused with MFA's step-up until its session steps up through
     * MFA, then allowed on the next request with the same token, through the
     * manager and the Gate alike; its other session is still refused.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testARequirementDeniesUntilTheSessionStepsUpThroughMfa(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $member = $this->member();
        $token  = $this->signIn($member);
        $other  = $this->signIn($member);
        $factor = $this->confirmedFactor($member);

        $refused = $this->request('POST', '/refund', $token);

        $refused->assertUnauthorized()
            ->assertJsonPath('error', StepUp::ERROR)
            ->assertJsonPath('requirement.multifactor', ['max_age' => null])
            ->assertJsonPath('has_confirmed_factor', true)
            ->assertJsonPath('factors.0.id', CodeTranslator::reference($factor));

        self::assertStringContainsString('insufficient_user_authentication', (string) $refused->headers->get('WWW-Authenticate'));

        $this->request('GET', '/can', $token)->assertOk()->assertExactJson(['manager' => false, 'gate' => false]);

        $this->request('POST', '/verify', $token, ['factor' => $factor->getKey(), 'code' => AuthenticatorApp::code($factor)])
            ->assertOk()
            ->assertExactJson(['verified' => true]);

        $this->request('POST', '/refund', $token)->assertOk()->assertExactJson(['refunded' => true]);
        $this->request('GET', '/can', $token)->assertOk()->assertExactJson(['manager' => true, 'gate' => true]);
        $this->request('POST', '/refund', $other)->assertUnauthorized()->assertJsonPath('error', StepUp::ERROR);
    }

    /**
     * A member acting in a tenant is listed the refund, in the caller's own
     * scope and in its tenant named, exactly when the check allows it: not
     * until its session steps up through MFA, and once it has, since
     * `laravel-authorization` judges a listing on the request's subject in the
     * scope's tenant, named by its own reference.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAListingInTheCallersTenantDecidesAsTheCheckDoes(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $this->app?->singleton(TenantResolver::class, OrganisationTenancy::class);
        $this->app?->singleton(TenantAccess::class, OrganisationTenancy::class);

        $member = $this->member();
        $token  = $this->signIn($member, self::TENANT);
        $factor = $this->confirmedFactor($member);

        $this->request('GET', '/listed', $token)->assertOk()->assertExactJson(['can' => false, 'current' => false, 'tenant' => false]);

        $this->request('POST', '/verify', $token, ['factor' => $factor->getKey(), 'code' => AuthenticatorApp::code($factor)])->assertOk();

        $this->request('GET', '/listed', $token)->assertOk()->assertExactJson(['can' => true, 'current' => true, 'tenant' => true]);
    }

    /**
     * A refusal about a member the caller names, which holds no session, is
     * Laravel's 403, not a step-up: no step-up by the caller could meet it, and
     * stepping up its own session changes nothing.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testARefusalAboutANamedMemberIsNoStepUp(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $member = $this->member();
        $named  = $this->member('grace@example.test');
        $token  = $this->signIn($member);
        $factor = $this->confirmedFactor($member);

        $this->request('POST', '/delegate', $token, ['member' => $named->getKey()])->assertForbidden();

        $this->request('POST', '/verify', $token, ['factor' => $factor->getKey(), 'code' => AuthenticatorApp::code($factor)])->assertOk();

        $this->request('POST', '/refund', $token)->assertOk();
        $this->request('POST', '/delegate', $token, ['member' => $named->getKey()])->assertForbidden();
    }

    /**
     * A member holding no confirmed factor is still asked to step up, told it
     * holds none, and offered nothing: a factor it has not confirmed counts for
     * neither.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAMemberWithNoConfirmedFactorIsToldItHoldsNone(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $member = $this->member();
        $token  = $this->signIn($member);

        $this->confirmedFactor($member)->forceFill(['status' => 'pending', 'confirmed_at' => null])->save();

        $this->request('POST', '/refund', $token)
            ->assertUnauthorized()
            ->assertJsonPath('error', StepUp::ERROR)
            ->assertJsonPath('has_confirmed_factor', false)
            ->assertJsonPath('factors', []);
    }

    /**
     * A requirement naming a level MFA does not know cannot be judged: its
     * allow never applies, whatever the session proved, and the refusal is
     * Laravel's 403 rather than a step-up nobody could meet.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testARequirementMfaCannotJudgeIsUndecidable(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $member = $this->member();
        $token  = $this->signIn($member);
        $factor = $this->confirmedFactor($member);

        $this->request('POST', '/verify', $token, ['factor' => $factor->getKey(), 'code' => AuthenticatorApp::code($factor)])->assertOk();

        $this->request('POST', '/void', $token)->assertForbidden();
    }

    /**
     * Define the routes the requests are made to, on the stateless guard and
     * with no session middleware.
     *
     * @param  mixed  $router
     * @return void
     */
    #[\Override]
    protected function defineRoutes(mixed $router): void
    {
        assert($router instanceof Router);

        $router->post('refund', static function (): JsonResponse {

            Authorization::authorize(self::REFUND);

            return new JsonResponse(['refunded' => true]);
        })->middleware('auth:' . self::GUARD);

        $router->post('delegate', static function (Request $request): JsonResponse {

            Authorization::for(Member::query()->findOrFail($request->integer('member')))->authorize(self::REFUND);

            return new JsonResponse(['refunded' => true]);
        })->middleware('auth:' . self::GUARD);

        $router->post('void', static function (): JsonResponse {

            Authorization::authorize(self::VOID);

            return new JsonResponse(['voided' => true]);
        })->middleware('auth:' . self::GUARD);

        $router->get('listed', static fn (): JsonResponse => new JsonResponse([
            'can'     => Authorization::can(self::REFUND),
            'current' => in_array(self::REFUND, Authorization::permissionsFor(null, AuthorizationScope::current()), true),
            'tenant'  => in_array(self::REFUND, Authorization::permissionsFor(null, AuthorizationScope::tenant(new Reference(Organisation::TYPE, self::TENANT))), true),
        ]))->middleware('auth:' . self::GUARD);

        $router->get('can', static fn (): JsonResponse => new JsonResponse(['manager' => Authorization::can(self::REFUND), 'gate' => Gate::allows(self::REFUND)]))
            ->middleware('auth:' . self::GUARD);

        $router->post('verify', static function (Request $request): JsonResponse {

            $result = Mfa::verify(CallerContext::fromRequest($request), Submission::factor($request->string('factor')->toString(), $request->string('code')->toString()));

            return new JsonResponse(['verified' => $result->isVerified()]);
        })->middleware('auth:' . self::GUARD);
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
     * A member whose only grant is a policy allowing a refund once its session
     * is multifactor, and a void once it reaches a level MFA does not know, the
     * one policy every member is attached to.
     *
     * @param  string  $email
     * @return \Tests\Fixtures\Authorization\Member
     */
    private function member(string $email = 'ada@example.test'): Member
    {
        $member = Member::query()->create(['name' => 'Ada Lovelace', 'email' => $email, 'password' => self::PASSWORD]);

        $member->attachPolicy(Policy::query()->firstOrCreate(['name' => 'refunds-after-step-up'], [
            'document' => [
                'statements' => [
                    [
                        'sid'        => 'refund-after-step-up',
                        'effect'     => 'allow',
                        'actions'    => [self::REFUND],
                        'conditions' => ['authentication_requirement' => ['authentication' => ['multifactor' => []]]],
                    ],
                    [
                        'sid'        => 'void-at-an-unknown-level',
                        'effect'     => 'allow',
                        'actions'    => [self::VOID],
                        'conditions' => ['authentication_requirement' => ['authentication' => ['assurance_level' => ['min' => 'gold']]]],
                    ],
                ],
            ],
        ]));

        return $member;
    }

    /**
     * Sign the member in with their password, into the tenant when one is
     * named, and return the session's access token.
     *
     * @param  \Tests\Fixtures\Authorization\Member  $member
     * @param  ?string  $tenant
     * @return string
     *
     * @throws \Throwable
     */
    private function signIn(Member $member, ?string $tenant = null): string
    {
        $auth = $this->app?->make('auth');

        self::assertInstanceOf(AuthManager::class, $auth);

        $client = new SignInContext(new ClientContext('192.0.2.10', 'iam-tests'), tenant: $tenant === null ? null : TenantSelection::of($tenant));
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
            'authenticatable_id'   => ProofOwner::of($member)->key,
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

    /**
     * Resolve the abstract from the application under test, as anything that
     * asks for it does.
     *
     * @param  string  $abstract
     * @return mixed
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function resolved(string $abstract): mixed
    {
        return $this->app?->make($abstract);
    }
}
