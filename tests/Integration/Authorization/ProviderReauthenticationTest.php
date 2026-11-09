<?php

declare(strict_types = 1);

namespace Tests\Integration\Authorization;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\JsonResponse;
use Illuminate\Routing\Router;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Sessions\AccessTokenResult;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker;
use SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement;
use SineMacula\Laravel\Authorization\Evaluation\RequirementResult;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Iam\Authorization\RequirementCheckerAdapter;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Mfa\RequirementCheckAdapter;
use SineMacula\Laravel\Mfa\Contracts\CombinationPolicy;
use SineMacula\Laravel\Mfa\Contracts\RequirementCheck;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Requirements\Requirement as MfaRequirement;
use SineMacula\Laravel\Sso\Contracts\EvidencePolicy;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken;
use Tests\Concerns\MigratesSso;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Sso\AcceptsTheProvidersContext;
use Tests\Fixtures\Sso\TrustsConnections;
use Tests\TestCase;

/**
 * Integration tests for a session's reauthentication at its provider, as
 * `laravel-authorization`'s requirement checker judges it (IAM-6.3): with a
 * combination policy that trusts the connection, as an application that trusts
 * its provider binds one, and SSO's evidence gate open, a reauthentication at
 * the provider meets a maximum age in MFA's route gate and in the checker
 * alike, so a policy statement gets the answer MFA's gate gives.
 *
 * Each scenario commits a sign-in and a reauthentication, and runs at the
 * connection's own level on every engine, then at READ COMMITTED and REPEATABLE
 * READ on MySQL and PostgreSQL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RequirementCheckerAdapter::class)]
#[CoversClass(RequirementCheckAdapter::class)]
final class ProviderReauthenticationTest extends TestCase
{
    use MigratesSso, RunsAtIsolationLevels, RunsSsoFlows, SignsInPeople;

    /** @var string The route MFA's gate holds to AAL2. */
    private const string AAL2_ROUTE = '/provider-reauthentication/aal2';

    /** @var int The maximum age, in seconds, the requirement allows its multifactor authentication. */
    private const int MAX_AGE = 900;

    /** @var \Tests\Fixtures\Models\Person The person who signs in through SSO. */
    private Person $person;

    /**
     * Arrange SSO with its evidence gate open, the person, and a combination
     * policy that trusts the connection.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeSso();

        $this->person = $this->createPerson();

        $this->app?->instance(CombinationPolicy::class, new TrustsConnections([$this->connectionId]));
        $this->app?->instance(EvidencePolicy::class, new AcceptsTheProvidersContext);
    }

    /**
     * A trusted provider's sign-in meets the maximum age until it is older than
     * that; the session's reauthentication at the provider then meets it again,
     * in MFA's route gate and in the authorization checker alike.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAReauthenticationAtTheProviderMeetsAMaximumAgeInTheGateAndTheChecker(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $this->freezeSecond();

        $session = $this->signInThroughSso();

        $this->actingOnSession($session, self::GUARD);

        self::assertTrue($this->isMetAtTheGate());
        self::assertTrue($this->checked($session)->isMet);

        $this->travel(self::MAX_AGE + 1)->seconds();

        self::assertFalse($this->isMetAtTheGate());
        self::assertEquals(RequirementResult::unmet(['multifactor']), $this->checked($session));

        $this->reauthenticateThroughSso($session);

        $this->actingOnSession($session, self::GUARD);

        self::assertTrue($this->isMetAtTheGate());
        $this->getJson(self::AAL2_ROUTE)->assertOk();

        self::assertTrue($this->checked($session)->isMet);
    }

    /**
     * Define the route MFA's gate holds to AAL2, on the stateless guard.
     *
     * @param  mixed  $router
     * @return void
     */
    #[\Override]
    protected function defineRoutes(mixed $router): void
    {
        assert($router instanceof Router);

        $router->get(self::AAL2_ROUTE, static fn (): JsonResponse => new JsonResponse(['reached' => true]))
            ->middleware(['auth:' . self::GUARD, 'mfa:level=aal2']);
    }

    /**
     * Link the person and sign them in through SSO, the provider asserting a
     * password and multifactor authentication, failing unless a session starts
     * active, and return it.
     *
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession
     *
     * @throws \Throwable
     */
    private function signInThroughSso(): EloquentSession&Model
    {
        $this->linkThroughFlow($this->person);

        $handoff = $this->handoff(tailor: self::multifactor(...));
        $answer  = Iam::signIns()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, new SignInContext(self::client()));

        self::assertInstanceOf(SignInResult::class, $answer);

        return $answer->session->record ?? self::fail('The sign-in established no session.');
    }

    /**
     * Reauthenticate the session at the provider, the provider asserting a
     * password and multifactor authentication again.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return void
     *
     * @throws \Throwable
     */
    private function reauthenticateThroughSso(EloquentSession&Model $session): void
    {
        $handoff = $this->handoff(Purpose::REAUTHENTICATE, $this->person, self::keyOf($session), self::multifactor(...));
        $token   = Iam::reauthentications()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, self::client());

        self::assertInstanceOf(AccessTokenResult::class, $token);
        self::assertFalse($token->isFailed(), (string) $token->reason?->value);
    }

    /**
     * The provider's token, asserting a password and multifactor
     * authentication.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken  $token
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken
     */
    private static function multifactor(FakeIdToken $token): FakeIdToken
    {
        return $token->with('amr', ['pwd', 'mfa']);
    }

    /**
     * Whether MFA's check, handed the proofs MFA's route gate reads of the
     * served session, finds multifactor authentication within the maximum age.
     *
     * @return bool
     *
     * @throws \Throwable
     */
    private function isMetAtTheGate(): bool
    {
        $check = $this->resolved(RequirementCheck::class);

        self::assertInstanceOf(RequirementCheck::class, $check);

        $requirement = MfaRequirement::none()->withMultifactor(self::MAX_AGE);

        return $check->check($requirement, ...Mfa::proofs(self::servedCaller()))->meetsRequirement();
    }

    /**
     * Ask the bound authorization checker whether the person's session meets
     * multifactor authentication within the maximum age.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return \SineMacula\Laravel\Authorization\Evaluation\RequirementResult
     *
     * @throws \Throwable
     */
    private function checked(EloquentSession&Model $session): RequirementResult
    {
        $checker = $this->resolved(AuthenticationRequirementChecker::class);

        self::assertInstanceOf(RequirementCheckerAdapter::class, $checker);

        $subject     = new Subject($this->person, $this->person, null, self::GUARD, self::GUARD, self::keyOf($session));
        $requirement = AuthenticationRequirement::fromOperand(['multifactor' => ['max_age' => self::MAX_AGE]]);

        return $checker->check($requirement, $subject);
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
