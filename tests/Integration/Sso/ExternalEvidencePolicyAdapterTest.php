<?php

declare(strict_types = 1);

namespace Tests\Integration\Sso;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Context\AuthenticationContext;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\ExternalEvidencePolicy;
use SineMacula\Laravel\Authentication\External\EvidenceSubject;
use SineMacula\Laravel\Authentication\External\ExternalEvidence;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose as AuthenticationPurpose;
use SineMacula\Laravel\Authentication\Requirements\Enums\AssuranceLevel;
use SineMacula\Laravel\Authentication\Requirements\LevelRequirement;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Sessions\AccessTokenResult;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Mfa\Translation\SignIn;
use SineMacula\Laravel\Iam\Sso\AdmittedRedemptions;
use SineMacula\Laravel\Iam\Sso\ConnectionTrust;
use SineMacula\Laravel\Iam\Sso\ExternalEvidencePolicyAdapter;
use SineMacula\Laravel\Mfa\Contracts\CombinationPolicy;
use SineMacula\Laravel\Mfa\Enums\ChannelKind as MfaChannelKind;
use SineMacula\Laravel\Mfa\Enums\ProofKind as MfaProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose as MfaPurpose;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Contracts\Enforcement;
use SineMacula\Laravel\Sso\Contracts\EvidencePolicy;
use SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose as FlowPurpose;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken;
use Tests\Concerns\MigratesSso;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Resolvers\ClaimedTenant;
use Tests\Fixtures\Sso\AcceptsTheProvidersContext;
use Tests\Fixtures\Sso\Redemptions;
use Tests\Fixtures\Sso\TrustsConnections;
use Tests\TestCase;

/**
 * Integration tests for the external evidence policy over SSO and MFA.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExternalEvidencePolicyAdapter::class)]
#[CoversClass(ConnectionTrust::class)]
final class ExternalEvidencePolicyAdapterTest extends TestCase
{
    use MigratesSso, RunsAtIsolationLevels, RunsSsoFlows, SignsInPeople;

    /** @var list<string> The methods the provider asserts. */
    private const array METHODS = ['pwd', 'mfa'];

    /** @var string The authentication context class the provider asserts. */
    private const string ACR = 'urn:example:acr:silver';

    /** @var string A tenant that owns no connection. */
    private const string OTHER_TENANT = 'tenant-2';

    /** @var \Tests\Fixtures\Models\Person The person whose evidence is judged. */
    private Person $person;

    /** @var \Carbon\CarbonImmutable When the provider authenticated the person. */
    private CarbonImmutable $authenticatedAt;

    /**
     * Arrange SSO, and the person.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeSso();

        $this->person          = $this->createPerson();
        $this->authenticatedAt = CarbonImmutable::now()->subMinute()->startOfSecond();
    }

    /**
     * The adapter is `laravel-authentication`'s external evidence policy.
     *
     * @return void
     */
    public function testTheAdapterIsAuthenticationsExternalEvidencePolicy(): void
    {
        self::assertInstanceOf(ExternalEvidencePolicyAdapter::class, $this->resolved(ExternalEvidencePolicy::class));
    }

    /**
     * With SSO's default evidence policy no evidence reaches either member.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testWithSsosDefaultNoEvidenceReachesAuthenticationOrMfa(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $this->trust([$this->connectionId]);

        $session = $this->signInThroughSso();

        self::assertNull($this->acceptedEvidenceOf($session));
        self::assertFalse($this->contextOn($session)->get('authentication.mfa'));
    }

    /**
     * With MFA's default policy a provider's `mfa` is not multifactor.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testWithMfasDefaultAProvidersMfaIsNotMultifactor(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $this->app?->instance(EvidencePolicy::class, new AcceptsTheProvidersContext);

        $session     = $this->signInThroughSso();
        $firstFactor = $this->firstFactorOf($session) ?? self::fail('The session has no first factor.');

        self::assertSame(ProofKind::FIRST_FACTOR, $firstFactor->kind);
        self::assertSame(ChannelKind::EXTERNAL_PROVIDER, $firstFactor->channel->kind);
        self::assertSame($this->connectionId, $firstFactor->channel->reference);
        self::assertNull($this->acceptedEvidenceOf($session));

        $context = $this->contextOn($session);

        $methods = $context->get('authentication.amr');

        self::assertFalse($context->get('authentication.mfa'));
        self::assertIsArray($methods);
        self::assertNotContains('mfa', $methods);
    }

    /**
     * Only a policy trusting the connection counts its accepted `mfa`.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testOnlyARebindingThatTrustsTheConnectionCountsItsMfa(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $this->app?->instance(EvidencePolicy::class, new AcceptsTheProvidersContext);

        $this->trust([$this->connectionId]);

        $session  = $this->signInThroughSso();
        $accepted = $this->acceptedEvidenceOf($session);

        self::assertIsArray($accepted);
        self::assertSame(self::METHODS, $accepted['methods'] ?? null);
        self::assertSame(self::ACR, $accepted['context'] ?? null);
        $context = $this->contextOn($session);

        self::assertTrue($context->get('authentication.mfa'));
        self::assertTrue($context->get('authentication.multifactor'));
    }

    /**
     * A policy trusting another connection counts nothing of this one's.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testARebindingThatTrustsAnotherConnectionCountsNothing(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $this->app?->instance(EvidencePolicy::class, new AcceptsTheProvidersContext);

        $this->trust(['another-connection']);

        $session = $this->signInThroughSso();

        self::assertNull($this->acceptedEvidenceOf($session));
        self::assertFalse($this->contextOn($session)->get('authentication.mfa'));
    }

    /**
     * A reauthentication records a `first_factor_reauthentication` for MFA.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAReauthenticationRecordsAFirstFactorReauthenticationForMfasReauthenticatePurpose(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $session = $this->signInThroughSso();

        $this->travel(30)->seconds();

        $handoff = $this->handoff(FlowPurpose::REAUTHENTICATE, $this->person, self::keyOf($session));
        $answer  = Iam::reauthentications()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, self::client());

        self::assertInstanceOf(AccessTokenResult::class, $answer);
        self::assertTrue($answer->isIssued());

        $newest = $this->sessions()->proofs($session)[0] ?? self::fail('The session has no proofs.');

        self::assertSame(
            [ProofKind::EXTERNAL_REAUTHENTICATION, AuthenticationPurpose::REAUTHENTICATE, 'external_provider', ChannelKind::EXTERNAL_PROVIDER, $this->connectionId],
            [$newest->kind, $newest->purpose, $newest->method, $newest->channel->kind, $newest->channel->reference],
        );

        $this->actingOnSession($session, self::GUARD);

        $proofs = Mfa::proofs(self::servedCaller());

        self::assertSame(
            [[MfaProofKind::FIRST_FACTOR, MfaPurpose::SIGN_IN], [MfaProofKind::FIRST_FACTOR_REAUTHENTICATION, MfaPurpose::REAUTHENTICATE]],
            array_map(static fn (Proof $proof): array => [$proof->kind, $proof->binding->purpose], $proofs),
        );

        $reauthentication = $proofs[1];

        self::assertSame(MfaChannelKind::EXTERNAL_PROVIDER, $reauthentication->channel?->kind);
        self::assertNull($reauthentication->channel->reference());
        self::assertSame(now()->getTimestamp(), $reauthentication->provedAt->getTimestamp());
    }

    /**
     * A `link` redemption records no proof.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testALinkRecordsNoProof(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $session = $this->signIn($this->person)->record;

        $this->actingOnSession($session, self::GUARD);

        $stored = DB::table('authentication_proofs')->count();
        $proofs = self::summaries(Mfa::proofs(self::servedCaller()));

        self::assertNotSame([], $proofs);

        $this->linkThroughFlow($this->person);

        self::assertSame($stored, DB::table('authentication_proofs')->count());
        self::assertSame($proofs, self::summaries(Mfa::proofs(self::servedCaller())));
    }

    /**
     * Rows of a probe requirement and whether a trusting policy meets it.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Requirements\Requirement, 1: bool}>
     */
    public static function provideProbes(): iterable
    {
        yield 'multifactor' => [new Requirement(multifactor: new RequirementPart), true];

        yield 'an additional verification' => [new Requirement(additionalVerification: new RequirementPart), true];

        yield 'phishing resistance' => [new Requirement(phishingResistance: new RequirementPart), false];

        yield 'a minimum level' => [new Requirement(minimumLevel: new LevelRequirement(AssuranceLevel::AAL1)), true];
    }

    /**
     * Admitted evidence is credible as MFA's combination policy says.
     *
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
     * @param  bool  $trusted
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideProbes')]
    public function testAdmittedEvidenceIsCredibleAsMfasPolicySays(Requirement $requirement, bool $trusted): void
    {
        $this->admitWith($this->accepted());

        self::assertFalse($this->adapter()->accepts($this->evidence(), $requirement, $this->subject()));

        $this->trust([$this->connectionId]);

        self::assertSame($trusted, $this->adapter()->accepts($this->evidence(), $requirement, $this->subject()));
    }

    /**
     * MFA is handed the sign-in's `external_provider` first factor.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testMfaIsHandedTheSignInsFirstFactor(): void
    {
        $policy = $this->trust([$this->connectionId]);

        $this->adapter()->meets($this->evidence(), self::multifactor(), $this->subject());

        self::assertCount(1, $policy->asked);
        self::assertCount(1, $policy->asked[0]);

        $proof = $policy->asked[0][0];

        self::assertSame(MfaProofKind::FIRST_FACTOR, $proof->kind);
        self::assertSame('external_provider', $proof->method);
        self::assertSame(MfaChannelKind::EXTERNAL_PROVIDER, $proof->channel?->kind);
        self::assertSame($this->connectionId, $proof->channel->reference());
        self::assertNull($proof->reference);
        self::assertSame($this->evidence()->authenticatedAt->getTimestamp(), $proof->provedAt->getTimestamp());
        self::assertSame([$this->person->getMorphClass(), (string) $this->person->id, self::GUARD, SignIn::UNNAMED, MfaPurpose::SIGN_IN], [
            $proof->binding->identityType,
            $proof->binding->identityKey,
            $proof->binding->application,
            $proof->binding->sessionId,
            $proof->binding->purpose,
        ]);
        self::assertSame(0, $proof->generation);
    }

    /**
     * Without an admitted redemption no evidence is accepted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEvidenceNoRedemptionAdmittedIsNeverAccepted(): void
    {
        $this->trust([$this->connectionId, 'connection-2']);

        self::assertFalse($this->adapter()->accepts($this->evidence(), self::multifactor(), $this->subject()));

        $this->admitWith($this->accepted());

        self::assertFalse($this->adapter()->accepts($this->evidence(), self::multifactor(), $this->subject('connection-2')));

        $this->app?->make(AdmittedRedemptions::class)->forget();
        $this->admitWith(null);

        self::assertFalse($this->adapter()->accepts($this->evidence(), self::multifactor(), $this->subject()));
    }

    /**
     * Rows of evidence that is not exactly what SSO accepted.
     *
     * @return iterable<string, array{0: list<string>, 1: ?string}>
     */
    public static function provideOtherEvidence(): iterable
    {
        yield 'a method more' => [[...self::METHODS, 'hwk'], self::ACR];

        yield 'the methods in another order' => [array_reverse(self::METHODS), self::ACR];

        yield 'no methods' => [[], self::ACR];

        yield 'another context' => [self::METHODS, 'urn:example:acr:gold'];

        yield 'no context' => [self::METHODS, null];
    }

    /**
     * Evidence other than what SSO accepted is never accepted.
     *
     * @param  list<string>  $methods
     * @param  ?string  $context
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideOtherEvidence')]
    public function testEvidenceOtherThanSsoAcceptedIsNeverAccepted(array $methods, ?string $context): void
    {
        $this->trust([$this->connectionId]);
        $this->admitWith($this->accepted());

        $other = new ExternalEvidence($methods, $context, $this->evidence()->authenticatedAt);

        self::assertFalse($this->adapter()->accepts($other, self::multifactor(), $this->subject()));
        self::assertTrue($this->adapter()->accepts($this->evidence(), self::multifactor(), $this->subject()));
    }

    /**
     * Evidence admitted for another identity is never accepted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEvidenceAdmittedForAnotherIdentityIsNeverAccepted(): void
    {
        $this->trust([$this->connectionId]);
        $this->admitWith($this->accepted());

        $other = new EvidenceSubject($this->createPerson(), self::GUARD, $this->connectionId, CarbonImmutable::now());

        self::assertFalse($this->adapter()->accepts($this->evidence(), self::multifactor(), $other));
        self::assertTrue($this->adapter()->accepts($this->evidence(), self::multifactor(), $this->subject()));
    }

    /**
     * Rows of offsets, in seconds, from the time SSO accepted the evidence for.
     *
     * @return iterable<string, array{0: int}>
     */
    public static function provideOtherTimes(): iterable
    {
        yield 'a second earlier' => [-1];

        yield 'a second later' => [1];

        yield 'an hour earlier' => [-3600];
    }

    /**
     * Evidence of another time is never accepted.
     *
     * @param  int  $offset
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideOtherTimes')]
    public function testEvidenceOfAnotherTimeIsNeverAccepted(int $offset): void
    {
        $this->trust([$this->connectionId]);
        $this->admitWith($this->accepted());

        $other = new ExternalEvidence(self::METHODS, self::ACR, $this->authenticatedAt->addSeconds($offset));

        self::assertFalse($this->adapter()->accepts($other, self::multifactor(), $this->subject()));
    }

    /**
     * Evidence dated after the subject's time is accepted as of that time.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEvidenceDatedAfterTheSubjectsTimeIsAcceptedAsOfIt(): void
    {
        $this->freezeSecond();
        $this->trust([$this->connectionId]);

        $future = CarbonImmutable::now()->addHour();

        $this->admitWith(new AcceptedEvidence($this->connectionId, $future, self::METHODS, self::ACR));

        $subject = $this->subject();

        self::assertTrue($this->adapter()->accepts(new ExternalEvidence(self::METHODS, self::ACR, $subject->now), self::multifactor(), $subject));
        self::assertFalse($this->adapter()->accepts(new ExternalEvidence(self::METHODS, self::ACR, $future), self::multifactor(), $subject));
    }

    /**
     * Accepted evidence meets a requirement within its maximum age.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAcceptedEvidenceMeetsARequirementWithinItsMaximumAge(): void
    {
        $fresh = new Requirement(multifactor: new RequirementPart(600));

        self::assertFalse($this->adapter()->meets($this->evidence(), $fresh, $this->subject()));

        $this->trust([$this->connectionId]);

        self::assertTrue($this->adapter()->meets($this->evidence(), $fresh, $this->subject()));

        $this->travel(601)->seconds();

        self::assertFalse($this->adapter()->meets($this->evidence(), $fresh, $this->subject()));
        self::assertTrue($this->adapter()->meets($this->evidence(), self::multifactor(), $this->subject()));
    }

    /**
     * A requirement that asks for nothing is never met.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequirementThatAsksForNothingIsNeverMet(): void
    {
        $policy = $this->trust([$this->connectionId]);

        $this->admitWith($this->accepted());

        self::assertFalse($this->adapter()->meets($this->evidence(), new Requirement, $this->subject()));
        self::assertFalse($this->adapter()->accepts($this->evidence(), new Requirement, $this->subject()));
        self::assertSame([], $policy->asked);
    }

    /**
     * A tenant trusts its own connections alone.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testATenantTrustsItsOwnConnectionsAlone(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $foreign = $this->connectionOf(self::OTHER_TENANT);

        $this->trust([$this->connectionId, $foreign, 'no-such-connection']);

        self::assertTrue($this->adapter()->meets($this->evidence(), self::multifactor(), $this->subject(tenant: self::TENANT)));
        self::assertFalse($this->adapter()->meets($this->evidence(), self::multifactor(), $this->subject(tenant: self::OTHER_TENANT)));
        self::assertTrue($this->adapter()->meets($this->evidence(), self::multifactor(), $this->subject($foreign, self::OTHER_TENANT)));
        self::assertFalse($this->adapter()->meets($this->evidence(), self::multifactor(), $this->subject($foreign, self::TENANT)));
        self::assertFalse($this->adapter()->meets($this->evidence(), self::multifactor(), $this->subject('no-such-connection', self::TENANT)));
    }

    /**
     * A tenant trusts the connections its enforcement names.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantTrustsTheConnectionsItsEnforcementNames(): void
    {
        $this->trust([$this->connectionId]);

        $enforcement = \Mockery::mock(Enforcement::class);

        $inherited = EnforcementPolicy::required(self::OTHER_TENANT, self::TENANT, [$this->connectionId], 'v1');

        $enforcement->allows('policy')->with(self::OTHER_TENANT, self::GUARD)->andReturn($inherited);
        $enforcement->allows('policy')->with(self::OTHER_TENANT, 'portal')->andReturn(EnforcementPolicy::notRequired(self::OTHER_TENANT, self::OTHER_TENANT));

        $this->app?->instance(Enforcement::class, $enforcement);

        self::assertTrue($this->adapter()->meets($this->evidence(), self::multifactor(), $this->subject(tenant: self::OTHER_TENANT)));
        self::assertFalse($this->adapter()->meets($this->evidence(), self::multifactor(), $this->subject(tenant: self::OTHER_TENANT, application: 'portal')));
    }

    /**
     * The tenant's trust is read only for evidence meeting the requirement.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheTenantsTrustIsReadOnlyForEvidenceThatMeetsTheRequirement(): void
    {
        $subject = $this->subject(tenant: self::TENANT);
        $queries = 0;

        DB::listen(static function () use (&$queries): void {
            $queries++;
        });

        self::assertFalse($this->adapter()->meets($this->evidence(), self::multifactor(), $subject));
        self::assertSame(0, $queries);
    }

    /**
     * A tenant that cannot be named throws.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantThatCannotBeNamedThrows(): void
    {
        $this->trust([$this->connectionId]);

        $this->expectException(UnresolvedReferenceException::class);

        $this->adapter()->meets($this->evidence(), self::multifactor(), $this->subject(tenant: ''));
    }

    /**
     * Bind a combination policy that trusts the connections, and return it.
     *
     * @param  list<string>  $connections
     * @return \Tests\Fixtures\Sso\TrustsConnections
     */
    private function trust(array $connections): TrustsConnections
    {
        $policy = new TrustsConnections($connections);

        $this->app?->instance(CombinationPolicy::class, $policy);

        return $policy;
    }

    /**
     * Record the sign-in SSO would admit, with the evidence it accepted.
     *
     * @param  ?\SineMacula\Laravel\Sso\Evidence\AcceptedEvidence  $evidence
     * @return void
     */
    private function admitWith(?AcceptedEvidence $evidence): void
    {
        $verified = Redemptions::verified(connectionId: $this->connectionId);

        $this->app?->make(AdmittedRedemptions::class)->record(RedemptionResult::redeemed(
            result: $verified,
            linkedIdentity: self::referenceOf($this->person),
            linkId: Redemptions::LINK,
            evidence: $evidence,
            admitted: true,
        ), Redemptions::client());
    }

    /**
     * The evidence SSO accepted through the connection.
     *
     * @return \SineMacula\Laravel\Sso\Evidence\AcceptedEvidence
     */
    private function accepted(): AcceptedEvidence
    {
        return new AcceptedEvidence($this->connectionId, $this->authenticatedAt, self::METHODS, self::ACR);
    }

    /**
     * The evidence `laravel-authentication` is handed of what SSO accepted.
     *
     * @return \SineMacula\Laravel\Authentication\External\ExternalEvidence
     */
    private function evidence(): ExternalEvidence
    {
        $accepted = $this->accepted();

        return new ExternalEvidence($accepted->methods(), $accepted->rawContext(), $accepted->authenticatedAt);
    }

    /**
     * The subject the evidence is judged for.
     *
     * @param  ?string  $connectionId
     * @param  ?string  $tenant
     * @param  string  $application
     * @return \SineMacula\Laravel\Authentication\External\EvidenceSubject
     */
    private function subject(?string $connectionId = null, ?string $tenant = null, string $application = self::GUARD): EvidenceSubject
    {
        return new EvidenceSubject($this->person, $application, $connectionId ?? $this->connectionId, CarbonImmutable::now(), $tenant === null ? null : new ClaimedTenant($tenant));
    }

    /**
     * A requirement of multifactor authentication of any age.
     *
     * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
     */
    private static function multifactor(): Requirement
    {
        return new Requirement(multifactor: new RequirementPart);
    }

    /**
     * The adapter, as `laravel-authentication` resolves it.
     *
     * @return \SineMacula\Laravel\Iam\Sso\ExternalEvidencePolicyAdapter
     */
    private function adapter(): ExternalEvidencePolicyAdapter
    {
        $adapter = $this->resolved(ExternalEvidencePolicy::class);

        return $adapter instanceof ExternalEvidencePolicyAdapter ? $adapter : self::fail('The adapter is not bound.');
    }

    /**
     * Create and enable an OIDC connection of the tenant, and answer its id.
     *
     * @param  string  $tenant
     * @return string
     */
    private function connectionOf(string $tenant): string
    {
        $provider    = $this->provider                             ?? self::fail('SSO is not arranged.');
        $connections = $this->app?->make(ConnectionService::class) ?? self::fail('The application has not booted.');
        $created     = $connections->create($tenant, 'oidc', 'Another OIDC', self::ssoClient(), [
            'issuer'                 => $provider->issuer,
            'authorization_endpoint' => $provider->endpoint('authorization'),
            'token_endpoint'         => $provider->endpoint('token'),
            'jwks_uri'               => $provider->endpoint('jwks'),
            'client_id'              => FakeOpenIdProvider::CLIENT_ID,
            'client_secret'          => FakeOpenIdProvider::CLIENT_SECRET,
        ]);

        return (string) $created->connection?->id;
    }

    /**
     * Sign the person in through SSO, and return the active session.
     *
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession
     *
     * @throws \Throwable
     */
    private function signInThroughSso(): EloquentSession&Model
    {
        $this->linkThroughFlow($this->person);

        $handoff = $this->handoff(tailor: static fn (FakeIdToken $token): FakeIdToken => $token->with('amr', self::METHODS)->with('acr', self::ACR));
        $answer  = Iam::signIns()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, new SignInContext(self::client()));

        self::assertInstanceOf(SignInResult::class, $answer);

        return $answer->session->record ?? self::fail('The sign-in established no session.');
    }

    /**
     * The evidence recorded as accepted with the session, or `null`.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $session
     * @return ?array<array-key, mixed>
     */
    private function acceptedEvidenceOf(Model $session): ?array
    {
        $stored = DB::table('authentication_provenance')->where('session_id', self::keyOf($session))->value('accepted_evidence');

        if ($stored === null) {
            return null;
        }

        $decoded = json_decode(is_string($stored) ? $stored : '', true, flags: JSON_THROW_ON_ERROR);

        return is_array($decoded) ? $decoded : self::fail('The accepted evidence is not a map.');
    }

    /**
     * The authentication context of a request served with the session.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return \SineMacula\Laravel\Authentication\Context\AuthenticationContext
     *
     * @throws \Throwable
     */
    private function contextOn(EloquentSession&Model $session): AuthenticationContext
    {
        $this->actingOnSession($session, self::GUARD);

        return Auth::context() ?? self::fail('No authentication context was built.');
    }

    /**
     * The proofs MFA holds, as their stored form.
     *
     * @param  list<\SineMacula\Laravel\Mfa\Proofs\Proof>  $proofs
     * @return list<array<string, mixed>>
     */
    private static function summaries(array $proofs): array
    {
        return array_map(static fn (Proof $proof): array => $proof->toArray(), $proofs);
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
