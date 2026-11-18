<?php

declare(strict_types = 1);

namespace Tests\Integration\Tenancy;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Sessions\RefreshResult;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;
use SineMacula\Laravel\Iam\Tenancy\TenantAuthenticationPolicyAdapter;
use SineMacula\Laravel\Iam\Tenancy\TenantPolicyVersion;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Verification\Submission;
use SineMacula\Laravel\Sso\Contracts\Enforcement;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Mfa\FactorChanges\Concerns\ArrangesFactorChanges;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Resolvers\ClaimedTenant;
use Tests\Fixtures\Resolvers\OpenTenancy;
use Tests\Fixtures\Tenancy\ScriptedEnforcement;
use Tests\Fixtures\Tenancy\ScriptedTenantRequirement;
use Tests\TestCase;

/**
 * Integration tests that a refresh judges the session against its tenant's
 * policy as it answers now, whether or not a change was reported.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TenantAuthenticationPolicyAdapter::class)]
#[CoversClass(TenantPolicyVersion::class)]
final class TenantPolicyRefreshTest extends TestCase
{
    use ArrangesFactorChanges, MigratesMembers, SignsInPeople;

    /** @var string The tenant the session acts in. */
    private const string TENANT = 'tenant-1';

    /** @var ?\Tests\Fixtures\Tenancy\ScriptedEnforcement SSO's enforcement, changed without a report. */
    private ?ScriptedEnforcement $enforcement = null;

    /**
     * Script SSO's enforcement, with an open tenancy and no identity factor.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Config::set('mfa.applications.' . self::GUARD . '.requirement', 'never');

        $this->enforcement = new ScriptedEnforcement;

        $this->app?->instance(Enforcement::class, $this->enforcement);
        $this->app?->instance(TenantResolver::class, new OpenTenancy);
        $this->app?->instance(TenantAccess::class, new OpenTenancy);
    }

    /**
     * A refresh after an unreported factor requirement returns the session to
     * pending, and verifying the factor records the new version.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshAfterAnUnreportedFactorRequirementReturnsToPending(): void
    {
        $requirements = ScriptedTenantRequirement::bind($this->app);
        $person       = $this->createPerson();
        $factor       = $this->confirmedFactor($person);
        $signedIn     = $this->signInTo($person);
        $before       = $this->stored($signedIn)->tenant_policy_version;
        $refreshed    = $this->refresh($signedIn);

        self::assertTrue($refreshed->isRefreshed(), (string) $refreshed->reason?->value);

        $requirements->require(self::TENANT, Requirement::none()->withMultifactor());

        $pending = $this->refresh($refreshed->session ?? self::fail('The refresh issued no session.'));

        self::assertTrue($pending->isPending(), (string) $pending->reason?->value);
        self::assertNull($pending->session);
        self::assertSame('pending', $this->stored($signedIn)->status);

        $credential = $pending->credential?->reveal() ?? self::fail('The pending refresh carries no credential.');
        $request    = Request::create('/mfa/verify', 'POST', ['pending_credential' => $credential]);
        $result     = Mfa::verify(CallerContext::fromRequest($request), Submission::factor($factor->getKey(), AuthenticatorApp::code($factor)));
        $current    = $this->currentVersionFor($person);

        self::assertTrue($result->isVerified());
        self::assertSame('active', $this->stored($signedIn)->status);
        self::assertNotSame($before, $current);
        self::assertSame($current, $this->stored($signedIn)->tenant_policy_version);
    }

    /**
     * A refresh after unreported SSO enforcement is refused and revokes the
     * password session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshAfterUnreportedSsoEnforcementIsRefused(): void
    {
        $signedIn = $this->signInTo($this->createPerson());

        $this->enforcement?->requireThrough(['connection-1']);

        $refused = $this->refresh($signedIn);

        self::assertTrue($refused->isFailed());
        self::assertSame(FailureReason::SSO_REQUIRED, $refused->reason);
        self::assertNull($refused->session);
        self::assertSame(RevocationReason::TENANT_POLICY_CHANGED->value, $this->stored($signedIn)->revoked_reason);
    }

    /**
     * The person's password sign-in to the tenant, failing unless active.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signInTo(Person $person): SignedInSession
    {
        $context = new SignInContext(self::client(), tenant: TenantSelection::of(self::TENANT));
        $result  = $this->sessions()->signIn('password', ['email' => $person->email, 'password' => self::PASSWORD], $context);

        self::assertTrue($result->isSignedIn(), (string) $result->reason?->value);

        return $result->session ?? self::fail('The sign-in established no session.');
    }

    /**
     * Refresh the signed-in session with its refresh token.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $signedIn
     * @return \SineMacula\Laravel\Authentication\Sessions\RefreshResult
     *
     * @throws \Throwable
     */
    private function refresh(SignedInSession $signedIn): RefreshResult
    {
        $presented = PresentedRefreshToken::fromBody($signedIn->tokens->refreshToken ?? self::fail('The session has no refresh token.'));

        return $this->sessions()->refresh($presented, self::client()) ?? self::fail('No refresh token was presented.');
    }

    /**
     * The version the tenant's policy answers for the person now.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return ?string
     */
    private function currentVersionFor(Person $person): ?string
    {
        $policy = $this->app?->make(TenantAuthenticationPolicy::class) ?? self::fail('The application has not booted.');

        return $policy->requirementFor(self::tenantPolicyContext($person, $person, new ClaimedTenant(self::TENANT), null, static fn (): ?string => null))->version;
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
}
