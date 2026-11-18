<?php

declare(strict_types = 1);

namespace Tests\Integration\EndToEnd;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SwitchResult;
use SineMacula\Laravel\Authentication\Sessions\SwitchTarget;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Iam\Tenancy\TenantAuthenticationPolicyAdapter;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Contracts\ActiveTenantResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Verification\Submission;
use SineMacula\Laravel\Sso\Enforcement\EnforcementService;
use Tests\Concerns\MigratesSso;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Mfa\FactorChanges\Concerns\ArrangesFactorChanges;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Resolvers\OpenTenancy;
use Tests\Fixtures\Tenancy\ScriptedTenantRequirement;
use Tests\TestCase;

/**
 * End-to-end tests of a session switching tenant, judged by the destination
 * tenant's authentication policy as this package binds it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TenantAuthenticationPolicyAdapter::class)]
final class TenantSwitchTest extends TestCase
{
    use ArrangesFactorChanges, MigratesSso, RunsSsoFlows, SignsInPeople;

    /** @var string A tenant that asks for a further factor. */
    private const string FACTOR_TENANT = 'tenant-2';

    /** @var string A tenant that requires sign-in through its connection. */
    private const string SSO_TENANT = 'tenant-3';

    /** @var ?\Tests\Fixtures\Tenancy\ScriptedTenantRequirement MFA's tenant requirement. */
    private ?ScriptedTenantRequirement $requirements = null;

    /**
     * Arrange SSO and an open tenancy, with only the identity's factor off.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeSso();

        Config::set('sso.features.enforcement', true);
        Config::set('mfa.applications.' . self::GUARD . '.requirement', 'never');

        $this->app?->instance(TenantResolver::class, new OpenTenancy);
        $this->app?->instance(TenantAccess::class, new OpenTenancy);

        $this->requirements = ScriptedTenantRequirement::bind($this->app);
    }

    /**
     * A switch into a tenant asking for a further factor waits pending until
     * the factor is verified, then acts in that tenant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchIntoATenantAskingForAFactorReturnsToPending(): void
    {
        $this->requirements()->require(self::FACTOR_TENANT, Requirement::none()->withMultifactor());

        $person   = $this->createPerson();
        $factor   = $this->confirmedFactor($person);
        $signedIn = $this->signInTo($person, self::TENANT);
        $switched = $this->switchTo($signedIn, self::FACTOR_TENANT);

        self::assertTrue($switched->isPending(), (string) $switched->reason?->value);
        self::assertNull($switched->session);
        self::assertSame(self::FACTOR_TENANT, $switched->pending?->tenant?->getTenantIdentifier());
        self::assertSame('pending', $this->stored($signedIn)->status);

        $credential = $switched->credential?->reveal() ?? self::fail('The pending switch carries no credential.');
        $request    = Request::create('/mfa/verify', 'POST', ['pending_credential' => $credential]);
        $result     = Mfa::verify(CallerContext::fromRequest($request), Submission::factor($factor->getKey(), AuthenticatorApp::code($factor)));

        self::assertTrue($result->isVerified());
        self::assertSame('active', $this->stored($signedIn)->status);
        self::assertSame(self::FACTOR_TENANT, $this->stored($signedIn)->tenant_id);
    }

    /**
     * A password session cannot switch into a tenant that enforces SSO, and
     * stays in its own tenant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPasswordSessionSwitchingIntoAnSsoEnforcingTenantIsRefused(): void
    {
        $this->enforceSsoIn(self::SSO_TENANT);

        $signedIn = $this->signInTo($this->createPerson(), self::TENANT);
        $switched = $this->switchTo($signedIn, self::SSO_TENANT);

        self::assertTrue($switched->isFailed());
        self::assertSame(FailureReason::SSO_REQUIRED, $switched->reason);
        self::assertNull($switched->session);
        self::assertSame(self::TENANT, $this->stored($signedIn)->tenant_id);
    }

    /**
     * After an allowed switch Authorization and MFA both read the new tenant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAllowedSwitchMovesAuthorizationAndMfaToTheNewTenant(): void
    {
        $this->enforceSsoIn(self::SSO_TENANT);

        $signedIn = $this->signInTo($this->createPerson(), self::TENANT);

        $this->request('/tenants', $signedIn->tokens->accessToken->reveal())
            ->assertOk()
            ->assertExactJson(['authorization' => self::TENANT, 'mfa' => self::TENANT]);

        $switched = $this->switchTo($signedIn, self::FACTOR_TENANT);

        self::assertTrue($switched->isSwitched(), (string) $switched->reason?->value);

        $token = $switched->session?->tokens->accessToken->reveal() ?? self::fail('The switch issued no access token.');

        $this->request('/tenants', $token)
            ->assertOk()
            ->assertExactJson(['authorization' => self::FACTOR_TENANT, 'mfa' => self::FACTOR_TENANT]);
        self::assertSame(self::FACTOR_TENANT, $this->stored($signedIn)->tenant_id);
        self::assertContains(['tenant' => self::FACTOR_TENANT, 'application' => self::GUARD], $this->requirements()->asked());
    }

    /**
     * Define the route that reports the tenant each member reads.
     *
     * @param  mixed  $router
     * @return void
     */
    #[\Override]
    protected function defineRoutes(mixed $router): void
    {
        assert($router instanceof Router);

        $router->get('tenants', static function (Request $request): JsonResponse {

            $person  = $request->user();
            $subject = Authorization::currentSubject();

            assert($person instanceof MultiFactorAuthenticatable);

            return new JsonResponse([
                'authorization' => $subject?->tenant instanceof Tenant ? $subject->tenant->getTenantIdentifier() : null,
                'mfa'           => app(ActiveTenantResolver::class)->activeTenant($person, self::GUARD),
            ]);
        })->middleware('auth:' . self::GUARD);
    }

    /**
     * Require sign-in to the tenant through a connection of its own.
     *
     * @param  string  $tenant
     * @return void
     */
    private function enforceSsoIn(string $tenant): void
    {
        $connection = $this->makeConnection($tenant);

        DB::table('sso_connections')->where('id', $connection)->update(['has_completed_sign_in' => true]);

        $enforcement = $this->app?->make(EnforcementService::class) ?? self::fail('The application has not booted.');
        $result      = $enforcement->update($tenant, true, [$connection], self::ssoClient());

        self::assertTrue($result->isChanged(), (string) $result->reason?->value);
    }

    /**
     * The person's password sign-in to the tenant, failing unless active.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  string  $tenant
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signInTo(Person $person, string $tenant): SignedInSession
    {
        $context = new SignInContext(self::client(), tenant: TenantSelection::of($tenant));
        $result  = $this->sessions()->signIn('password', ['email' => $person->email, 'password' => self::PASSWORD], $context);

        self::assertTrue($result->isSignedIn(), (string) $result->reason?->value);

        return $result->session ?? self::fail('The sign-in established no session.');
    }

    /**
     * Switch the signed-in session to the tenant with its refresh token.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $signedIn
     * @param  string  $tenant
     * @return \SineMacula\Laravel\Authentication\Sessions\SwitchResult
     *
     * @throws \Throwable
     */
    private function switchTo(SignedInSession $signedIn, string $tenant): SwitchResult
    {
        $presented = PresentedRefreshToken::fromBody($signedIn->tokens->refreshToken ?? self::fail('The session has no refresh token.'));

        return $this->sessions()->switchTo($presented, SwitchTarget::tenant(TenantSelection::of($tenant)), self::client());
    }

    /**
     * The session's row as stored now.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $signedIn
     * @return \stdClass
     */
    private function stored(SignedInSession $signedIn): \stdClass
    {
        return DB::table('authentication_sessions')->where('id', $signedIn->record->getKey())->first() ?? self::fail('The session was not stored.');
    }

    /**
     * Make a fresh request with the bearer token.
     *
     * @param  string  $uri
     * @param  string  $token
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     *
     * @throws \Throwable
     */
    private function request(string $uri, string $token): TestResponse
    {
        $auth = $this->app?->make('auth');

        self::assertInstanceOf(AuthManager::class, $auth);

        $auth->forgetGuardState();

        return $this->withToken($token)->getJson($uri);
    }

    /**
     * MFA's tenant requirement, as the test scripts it.
     *
     * @return \Tests\Fixtures\Tenancy\ScriptedTenantRequirement
     */
    private function requirements(): ScriptedTenantRequirement
    {
        return $this->requirements ?? self::fail('The requirement is not arranged.');
    }
}
