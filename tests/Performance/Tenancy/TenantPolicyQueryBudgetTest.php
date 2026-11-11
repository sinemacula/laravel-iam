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
 * The statements a sign-in and a refresh in a tenant make with the tenant
 * authentication policy this package binds (IAM-4.5), so a read the policy
 * adds, for SSO's enforcement, the session's connection or the application's
 * requirement, is seen here.
 *
 * With SSO's enforcement off and no tenant MFA requirement, the policy reads
 * nothing at all. With the enforcement on, it reads the enforcing tenant's
 * rule and its satisfying connections, two plain reads on every call, never
 * cached; for a session (a refresh), it asks for the connection the session's
 * provenance records too, a third read, which `laravel-authentication` makes
 * once for the policy and its own judgement; a sign-in through SSO is judged by
 * the connection its evidence names, with no read at all. The application's tenant
 * MFA requirement costs whatever the application's own reads cost, and the
 * fake's none.
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
     * Arrange SSO, a tenancy in which everyone may act in every tenant, and a
     * linked person who has signed in once through the connection, as SSO
     * requires before it enforces one.
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
        // Reads (8): the person by email, MFA's three for the additional-factor
        // policy, laravel-authentication's three of the new session's proofs
        // and provenance, and the person the guard binds; the policy reads
        // nothing. Writes (11): laravel-authentication's attempt counters
        // (counted, then forgiven once signed in), the session and its first
        // proof. Transactions: laravel-authentication's, begun and committed.
        $person = $this->createPerson();
        $answer = $this->assertQueryBudget(8, 11, fn (): SignInResult => $this->signInWithPassword($person), begins: 1, commits: 1);

        self::assertTrue($answer->isSignedIn());
    }

    /**
     * A password sign-in in a tenant whose MFA requirement the application's
     * fake answers, which reads nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPasswordSignInWithATenantRequirement(): void
    {
        ScriptedTenantRequirement::bind($this->app)->require(self::TENANT, MfaRequirement::none()->withMultifactor());

        // Reads (8): as with nothing on, less the proofs the active session's
        // context reads, plus MFA's own read of the verification generation for
        // the further factor the tenant requires; the fake reads nothing, and
        // so the policy nothing of its own. Writes (8): the attempt counters,
        // kept while the sign-in is pending, the session and its first proof.
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

        // Reads (18): SSO's six (the code by its digest, the connection's
        // tenant, then under the locks the enforcing tenant's rule, the
        // connections, the code and the link); the identity, twice; MFA's three;
        // the policy's two, the rule and its connections, the sign-in judged by
        // the connection its evidence names, with no read of its own;
        // laravel-authentication's three of the new session's proofs and
        // provenance; and the two the guard binds the session with. Writes (9):
        // SSO's (the attempt counted, the rule's lock row, the code recorded as
        // used and consumed, the link's last use) and laravel-authentication's
        // four (the link's connection guard, the session, its first proof, its
        // provenance). Transactions: as for a sign-in with no rule.
        $handoff = $this->handoff();
        $answer  = $this->assertQueryBudget(18, 9, fn (): RedemptionResult|SignInResult => $this->redeemInTenant($handoff->code, $handoff->verifier), begins: 5, commits: 5);

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
        // Reads (5): the attempt counters, the session, then under its issuance
        // guard the session again, the person and its proofs; the policy reads
        // nothing. Writes (2): the issuance guard and the rotation.
        // Transactions: laravel-authentication's, begun and committed.
        $token   = $this->refreshTokenOf($this->redeemInTenant());
        $refresh = fn (): RefreshResult => $this->sessions()->refresh(PresentedRefreshToken::fromBody($token), self::client());
        $answer  = $this->assertQueryBudget(5, 2, $refresh, begins: 1, commits: 1);

        self::assertFalse($answer->isFailed());
    }

    /**
     * A refresh of a session through a satisfying connection, in an enforcing
     * tenant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshInAnEnforcingTenant(): void
    {
        $this->enforce();

        // Reads (8): as with nothing on, and the policy's three, the rule, its
        // connections and the connection the session's provenance records, read
        // current once by laravel-authentication for the policy and its own
        // judgement alike. Writes (2) and transactions: as with nothing on.
        $token   = $this->refreshTokenOf($this->redeemInTenant());
        $refresh = fn (): RefreshResult => $this->sessions()->refresh(PresentedRefreshToken::fromBody($token), self::client());
        $answer  = $this->assertQueryBudget(8, 2, $refresh, begins: 1, commits: 1);

        self::assertFalse($answer->isFailed());
    }

    /**
     * Require every session acting in the tenant to come through the tests'
     * connection.
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
     * Redeem a handoff for the guard through the connection, the sign-in asking
     * to act in the tenant: the one given, or a new one.
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
