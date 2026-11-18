<?php

declare(strict_types = 1);

namespace Tests\Integration\EndToEnd;

use Illuminate\Http\JsonResponse;
use Illuminate\Routing\Router;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus;
use SineMacula\Laravel\Authentication\Sessions\FactorRemoval;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Iam\Mfa\PendingCompletionAdapter;
use SineMacula\Laravel\Iam\Mfa\SessionRevokerAdapter;
use SineMacula\Laravel\Mfa\Contracts\IdentityRequirement;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Fixtures\Mfa\FactorChanges\Concerns\ArrangesFactorChanges;
use Tests\Fixtures\Mfa\Pending\Concerns\ArrangesPendingSessions;
use Tests\TestCase;

/**
 * End-to-end tests of a factor removal that leaves the session pending.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionRevokerAdapter::class)]
#[CoversClass(PendingCompletionAdapter::class)]
final class FactorRemovalPendingTest extends TestCase
{
    use ArrangesFactorChanges, ArrangesPendingSessions;

    /** @var int How old a further factor may be for the identity's requirement, in seconds. */
    private const int MAX_AGE = 300;

    /** @var string The route the guard and MFA's gate both guard. */
    private const string GATED_ROUTE = '/gated';

    /**
     * The kept factor completes the pending session a removal leaves behind.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheKeptFactorReactivatesTheSessionARemovalLeftPending(): void
    {
        $this->requireARecentFurtherFactor();

        $person   = $this->createPerson();
        $signedIn = $this->signIn($person);
        $session  = $signedIn->record;
        $token    = $signedIn->tokens->accessToken->reveal();

        $this->actingOnSession($session);

        [$removed, $kept] = [$this->confirmedFactor($person), $this->confirmedFactor($person)];

        $this->stepUpThroughMfa($kept);
        $this->travel(self::MAX_AGE + 100)->seconds();
        $this->stepUpThroughMfa($removed);

        $this->request($token)->assertOk();

        $removal    = Mfa::removeFactor(self::servedCaller(), $removed->id);
        $completion = $removal->completion();

        self::assertTrue($removal->wasMade(), (string) $removal->reason?->value);
        self::assertInstanceOf(FactorRemoval::class, $completion);
        self::assertTrue($completion->isPending());
        self::assertSame(SessionStatus::PENDING, Session::query()->whereKey($session->getKey())->sole()->getStatus());

        $this->request($token)->assertUnauthorized();

        $credential = $completion->credential?->reveal() ?? self::fail('The removal handed back no pending credential.');
        $result     = Mfa::verify(self::servedCaller(self::requestCarrying($credential)), Submission::factor($kept->id, AuthenticatorApp::code($kept)));
        $signIn     = $result->completion();

        self::assertTrue($result->isVerified(), (string) $result->reason?->value);
        self::assertInstanceOf(SignInResult::class, $signIn);
        self::assertTrue($signIn->isSignedIn(), (string) $signIn->reason?->value);

        $reactivated = $signIn->session ?? self::fail('No session was signed in.');

        self::assertSame($session->getKey(), $reactivated->record->getKey());
        self::assertSame(SessionStatus::ACTIVE, Session::query()->whereKey($session->getKey())->sole()->getStatus());

        $this->request($reactivated->tokens->accessToken->reveal())->assertOk();
    }

    /**
     * How old a further factor may be, in seconds.
     *
     * @return int
     */
    public static function maxAge(): int
    {
        return self::MAX_AGE;
    }

    /**
     * Define the route the guard and MFA's gate both guard.
     *
     * @param  mixed  $router
     * @return void
     */
    #[\Override]
    protected function defineRoutes(mixed $router): void
    {
        assert($router instanceof Router);

        $router->get(self::GATED_ROUTE, static fn (): JsonResponse => new JsonResponse(['reached' => true]))
            ->middleware(['auth:' . self::GUARD, 'mfa']);
    }

    /**
     * Have MFA ask an identity holding a factor for a recent further factor.
     *
     * @return void
     */
    private function requireARecentFurtherFactor(): void
    {
        $this->app?->instance(IdentityRequirement::class, new class implements IdentityRequirement {
            /**
             * Ask an identity holding a factor for a recent further factor.
             *
             * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
             * @param  string  $application
             * @return \SineMacula\Laravel\Mfa\Requirements\Requirement
             */
            #[\Override]
            public function requirementFor(MultiFactorAuthenticatable $identity, string $application): Requirement
            {
                return $identity->isMfaEnabled() ? Requirement::none()->withAdditionalVerification(FactorRemovalPendingTest::maxAge()) : Requirement::none();
            }
        });
    }

    /**
     * Step the acting session up through MFA with the factor's current code.
     *
     * @param  \SineMacula\Laravel\Mfa\Models\Factor  $factor
     * @return void
     *
     * @throws \Throwable
     */
    private function stepUpThroughMfa(Factor $factor): void
    {
        $result = Mfa::verify(self::servedCaller(), Submission::factor($factor->id, AuthenticatorApp::code($factor)), Purpose::STEP_UP);

        self::assertTrue($result->isVerified(), (string) $result->reason?->value);
    }

    /**
     * Call the gated route as a new request bearing the access token.
     *
     * @param  string  $token
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function request(string $token): TestResponse
    {
        $auth = $this->app?->make('auth');

        self::assertInstanceOf(AuthManager::class, $auth);

        $auth->forgetGuardState();

        return $this->withToken($token)->getJson(self::GATED_ROUTE);
    }
}
