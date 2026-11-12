<?php

declare(strict_types = 1);

namespace Tests\Integration\Sso;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\JsonResponse;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\External\ExternalEvidence;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Requirements\Enums\RequirementKind;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementEvaluation;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Requirements\RequirementSubject;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Mfa\ProofStoreAdapter;
use SineMacula\Laravel\Iam\Mfa\RequirementCheckAdapter;
use SineMacula\Laravel\Iam\Mfa\SignInProofs;
use SineMacula\Laravel\Iam\Mfa\Translation\ProofTranslator;
use SineMacula\Laravel\Iam\Mfa\Translation\ProviderTrust;
use SineMacula\Laravel\Iam\Mfa\Translation\SignIn;
use SineMacula\Laravel\Iam\Sso\ConnectionTrust;
use SineMacula\Laravel\Mfa\Contracts\CombinationPolicy;
use SineMacula\Laravel\Mfa\Enums\ChannelKind as MfaChannelKind;
use SineMacula\Laravel\Mfa\Enums\ProofKind as MfaProofKind;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Sso\Contracts\EvidencePolicy;
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
 * Integration tests for when MFA sees an SSO first factor naming its
 * connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProofTranslator::class)]
#[CoversClass(ProviderTrust::class)]
#[CoversClass(ConnectionTrust::class)]
#[CoversClass(ProofStoreAdapter::class)]
#[CoversClass(SignInProofs::class)]
#[CoversClass(RequirementCheckAdapter::class)]
final class ProviderTrustTest extends TestCase
{
    use MigratesSso, RunsAtIsolationLevels, RunsSsoFlows, SignsInPeople;

    /** @var string The route MFA's gate holds to AAL2. */
    private const string AAL2_ROUTE = '/provider-trust/aal2';

    /** @var string A tenant that owns no connection. */
    private const string OTHER_TENANT = 'tenant-2';

    /** @var \Tests\Fixtures\Models\Person The person who signs in through SSO. */
    private Person $person;

    /**
     * Arrange SSO, the person, and a combination policy that trusts the
     * connection.
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
    }

    /**
     * With SSO's evidence gate closed, a trusted connection counts for nothing.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testATrustedConnectionCountsNothingSsoDidNotAccept(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $session = $this->signInThroughSso(['pwd']);

        self::assertNull(DB::table('authentication_provenance')->where('session_id', self::keyOf($session))->value('accepted_evidence'));
        self::assertContains(RequirementKind::MULTIFACTOR, $this->checked($session)->unmet);

        $this->actingOnSession($session, self::GUARD);

        self::assertNull($this->mfasFirstFactorChannel());

        $this->getJson(self::AAL2_ROUTE)->assertUnauthorized();
    }

    /**
     * Evidence SSO accepted from a trusted connection passes MFA's route gate.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testEvidenceSsoAcceptedFromATrustedConnectionPassesMfasGate(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $this->app?->instance(EvidencePolicy::class, new AcceptsTheProvidersContext);

        $session = $this->signInThroughSso(['pwd', 'mfa']);

        self::assertNotNull(DB::table('authentication_provenance')->where('session_id', self::keyOf($session))->value('accepted_evidence'));
        self::assertContains(RequirementKind::MULTIFACTOR, $this->checked($session)->unmet);

        $this->actingOnSession($session, self::GUARD);

        self::assertSame($this->connectionId, $this->mfasFirstFactorChannel());

        $this->getJson(self::AAL2_ROUTE)->assertOk();
    }

    /**
     * Rows of the session's tenant and whether MFA sees the connection named.
     *
     * @return iterable<string, array{0: ?string, 1: bool}>
     */
    public static function provideTenants(): iterable
    {
        yield 'no tenant' => [null, true];

        yield 'the connection\'s own tenant' => [self::TENANT, true];

        yield 'another tenant' => [self::OTHER_TENANT, false];
    }

    /**
     * An accepted first factor names its connection only for a tenant that
     * trusts it.
     *
     * @param  ?string  $tenant
     * @param  bool  $named
     * @return void
     */
    #[DataProvider('provideTenants')]
    public function testAnAcceptedFirstFactorNamesItsConnectionOnlyForATenantThatTrustsIt(?string $tenant, bool $named): void
    {
        $proof = $this->translator()->toMfa($this->externalFirstFactor($this->connectionId), $this->unnamedSignIn(), ProviderTrust::accepted($tenant));

        self::assertSame(MfaChannelKind::EXTERNAL_PROVIDER, $proof->channel?->kind);
        self::assertSame($named ? $this->connectionId : null, $proof->channel->reference());
    }

    /**
     * Without enforcement, a tenant trusts its own connection alone.
     *
     * @return void
     */
    public function testWithoutEnforcementATenantTrustsItsOwnConnectionAlone(): void
    {
        $trust = $this->app?->make(ConnectionTrust::class) ?? self::fail('The application has not booted.');

        self::assertTrue($trust->trusts(self::TENANT, $this->connectionId, self::GUARD));
        self::assertFalse($trust->trusts(self::OTHER_TENANT, $this->connectionId, self::GUARD));
        self::assertFalse($trust->trusts(self::TENANT, 'no-such-connection', self::GUARD));
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
     * Link and sign the person in through SSO with the given methods, and
     * return the active session.
     *
     * @param  list<string>  $methods
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession
     *
     * @throws \Throwable
     */
    private function signInThroughSso(array $methods): EloquentSession&Model
    {
        $this->linkThroughFlow($this->person);

        $handoff = $this->handoff(tailor: static fn (FakeIdToken $token): FakeIdToken => $token->with('amr', $methods));
        $answer  = Iam::signIns()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, new SignInContext(self::client()));

        self::assertInstanceOf(SignInResult::class, $answer);

        return $answer->session->record ?? self::fail('The sign-in established no session.');
    }

    /**
     * What the bound requirement check leaves unmet of a multifactor
     * requirement.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return \SineMacula\Laravel\Authentication\Requirements\RequirementEvaluation
     *
     * @throws \Throwable
     */
    private function checked(EloquentSession&Model $session): RequirementEvaluation
    {
        $check       = $this->resolved(RequirementCheck::class);
        $firstFactor = $this->firstFactorOf($session) ?? self::fail('The session has no first factor.');

        self::assertInstanceOf(RequirementCheckAdapter::class, $check);

        $subject = new RequirementSubject($this->person, self::GUARD, $session, $firstFactor, CarbonImmutable::now(), static fn (): array => []);

        return $check->evaluate($subject, new Requirement(multifactor: new RequirementPart));
    }

    /**
     * The connection the served session's external first factor names to MFA.
     *
     * @return ?string
     *
     * @throws \Throwable
     */
    private function mfasFirstFactorChannel(): ?string
    {
        $proof = Mfa::proofs(self::servedCaller())[0] ?? self::fail('MFA holds no proof of the session.');

        self::assertSame(MfaProofKind::FIRST_FACTOR, $proof->kind);
        self::assertSame(MfaChannelKind::EXTERNAL_PROVIDER, $proof->channel?->kind);

        return $proof->channel->reference();
    }

    /**
     * An SSO first factor through the connection, carrying accepted evidence.
     *
     * @param  string  $connectionId
     * @return \SineMacula\Laravel\Authentication\Proofs\RecordedProof
     */
    private function externalFirstFactor(string $connectionId): RecordedProof
    {
        $now = CarbonImmutable::now()->startOfSecond();

        return new RecordedProof(
            'proof-1',
            ProofKind::FIRST_FACTOR,
            Purpose::SIGN_IN,
            'external_provider',
            new Channel(ChannelKind::EXTERNAL_PROVIDER, $connectionId),
            null,
            new ObservedProperties,
            null,
            ['pwd', 'mfa'],
            $now,
            new ExternalEvidence(['pwd', 'mfa'], null, $now),
        );
    }

    /**
     * The sign-in no session key names yet, of the person on the guard.
     *
     * @return \SineMacula\Laravel\Iam\Mfa\Translation\SignIn
     */
    private function unnamedSignIn(): SignIn
    {
        return new SignIn(ProofOwner::of($this->person), self::GUARD, SignIn::UNNAMED, 0);
    }

    /**
     * The proof translator, as the container builds it.
     *
     * @return \SineMacula\Laravel\Iam\Mfa\Translation\ProofTranslator
     */
    private function translator(): ProofTranslator
    {
        return $this->app?->make(ProofTranslator::class) ?? self::fail('The application has not booted.');
    }

    /**
     * What the container resolves the abstract to.
     *
     * @param  string  $abstract
     * @return mixed
     */
    private function resolved(string $abstract): mixed
    {
        return $this->app?->make($abstract);
    }
}
