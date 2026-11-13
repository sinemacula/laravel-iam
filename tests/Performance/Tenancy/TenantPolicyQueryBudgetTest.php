<?php

declare(strict_types = 1);

namespace Tests\Performance\Tenancy;

use Illuminate\Support\Facades\Config;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\Sessions\RefreshResult;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Tenancy\TenantAuthenticationPolicyAdapter;
use SineMacula\Laravel\Mfa\Requirements\Requirement as MfaRequirement;
use SineMacula\Laravel\Sso\Enforcement\EnforcementService;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use Tests\Concerns\MigratesSso;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Resolvers\OpenTenancy;
use Tests\Fixtures\Tenancy\ScriptedTenantRequirement;
use Tests\Performance\PerformanceContractTestCase;

/**
 * Query budgets for sign-ins and refreshes under the tenant policy.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TenantAuthenticationPolicyAdapter::class)]
final class TenantPolicyQueryBudgetTest extends PerformanceContractTestCase
{
    use MigratesSso, RunsSsoFlows, SignsInPeople;

    /**
     * Arrange SSO, an open tenancy and a linked person who has signed in once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeSso();

        $this->app?->instance(TenantResolver::class, new OpenTenancy);
        $this->app?->instance(TenantAccess::class, new OpenTenancy);

        $this->linkThroughFlow($this->createPerson());

        self::assertInstanceOf(SignInResult::class, $this->redeemInTenant());
    }

    /**
     * A password sign-in in a tenant, with nothing on.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPasswordSignInWithNothingOn(): void
    {
        // Reads: person, MFA's three, the session's three proofs and
        // provenance, and the guard's person; the policy reads nothing. Writes:
        // attempt counters, the session and its first proof.
        $person = $this->createPerson();
        $answer = $this->assertQueryBudget(8, 11, fn (): SignInResult => $this->signInWithPassword($person), begins: 1, commits: 1);

        self::assertTrue($answer->isSignedIn());
    }

    /**
     * A password sign-in under a tenant requirement the fake answers.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPasswordSignInWithATenantRequirement(): void
    {
        ScriptedTenantRequirement::bind($this->app)->require(self::TENANT, MfaRequirement::none()->withMultifactor());

        // As with nothing on, less the context's proofs, plus MFA's generation
        // read; the fake reads nothing. Writes: counters, session, first proof.
        $person = $this->createPerson();
        $answer = $this->assertQueryBudget(8, 8, fn (): SignInResult => $this->signInWithPassword($person), begins: 1, commits: 1);

        self::assertFalse($answer->isFailed());
    }

    /**
     * A linked sign-in through SSO in an enforcing tenant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALinkedSignInInAnEnforcingTenant(): void
    {
        $this->enforce();

        // Reads: SSO's six, the identity twice, MFA's three, the policy's two
        // (rule and connections), the session's three, the guard's two, and the
        // check after commit's rule, connections and session connection.
        // Writes: SSO's five and laravel-authentication's four.
        $handoff = $this->handoff();
        $answer  = $this->assertQueryBudget(21, 9, fn (): RedemptionResult|SignInResult => $this->redeemInTenant($handoff->code, $handoff->verifier), begins: 5, commits: 5);

        self::assertInstanceOf(SignInResult::class, $answer);
        self::assertTrue($answer->isSignedIn());
    }

    /**
     * A refresh of a session in a tenant, with nothing on.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshWithNothingOn(): void
    {
        // Reads: counters, the session, then under its guard the session,
        // person and proofs; the policy reads nothing. Writes: the guard and
        // rotation.
        $token   = $this->refreshTokenOf($this->redeemInTenant());
        $refresh = fn (): RefreshResult => $this->sessions()->refresh(PresentedRefreshToken::fromBody($token), self::client());
        $answer  = $this->assertQueryBudget(5, 2, $refresh, begins: 1, commits: 1);

        self::assertFalse($answer->isFailed());
    }

    /**
     * A refresh through a satisfying connection in an enforcing tenant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshInAnEnforcingTenant(): void
    {
        $this->enforce();

        // As with nothing on, plus the policy's rule, connections and
        // provenance connection, read once for the policy and the judgement.
        $token   = $this->refreshTokenOf($this->redeemInTenant());
        $refresh = fn (): RefreshResult => $this->sessions()->refresh(PresentedRefreshToken::fromBody($token), self::client());
        $answer  = $this->assertQueryBudget(8, 2, $refresh, begins: 1, commits: 1);

        self::assertFalse($answer->isFailed());
    }

    /**
     * Require sessions in the tenant to come through the tests' connection.
     *
     * @return void
     */
    private function enforce(): void
    {
        Config::set('sso.features.enforcement', true);

        $result = $this->app?->make(EnforcementService::class)->update(self::TENANT, true, [$this->connectionId], self::ssoClient());

        self::assertTrue($result?->isChanged());
    }

    /**
     * Redeem a handoff in the tenant, the given one or a new one.
     *
     * @param  ?string  $code
     * @param  ?string  $verifier
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult|\SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     *
     * @throws \Throwable
     */
    private function redeemInTenant(?string $code = null, ?string $verifier = null): RedemptionResult|SignInResult
    {
        if ($code === null || $verifier === null) {
            $handoff  = $this->handoff();
            $code     = $handoff->code;
            $verifier = $handoff->verifier;
        }

        return Iam::signIns()->redeem(self::GUARD, $this->connectionId, $code, $verifier, new SignInContext(self::client(), tenant: TenantSelection::of(self::TENANT)));
    }

    /**
     * Sign the person in with their password, asking to act in the tenant.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    private function signInWithPassword(Person $person): SignInResult
    {
        $context = new SignInContext(self::client(), tenant: TenantSelection::of(self::TENANT));

        return $this->sessions()->signIn('password', ['email' => $person->email, 'password' => self::PASSWORD], $context);
    }

    /**
     * The refresh token the sign-in issued, failing unless it signed in.
     *
     * @param  mixed  $answer
     * @return \SineMacula\Laravel\Authentication\Secrets\Secret
     */
    private function refreshTokenOf(mixed $answer): Secret
    {
        self::assertInstanceOf(SignInResult::class, $answer);

        return $answer->session?->tokens->refreshToken ?? self::fail('No refresh token.');
    }
}
