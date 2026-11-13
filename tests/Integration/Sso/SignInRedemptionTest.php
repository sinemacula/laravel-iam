<?php

declare(strict_types = 1);

namespace Tests\Integration\Sso;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason as AuthenticationFailure;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose as ProofPurpose;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding;
use SineMacula\Laravel\Authentication\Proofs\ProofResult;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Authentication\Sessions\SwitchTarget;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\ExternalSignInRefusedException;
use SineMacula\Laravel\Iam\Exceptions\UnlinkedSignInException;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Sso\AdmittedRedemptions;
use SineMacula\Laravel\Iam\Sso\ExternalResults;
use SineMacula\Laravel\Iam\Sso\SignInRedemption;
use SineMacula\Laravel\Iam\Sso\Translation\ClientTranslator;
use SineMacula\Laravel\Sso\Contracts\EvidencePolicy;
use SineMacula\Laravel\Sso\Enforcement\EnforcementResult;
use SineMacula\Laravel\Sso\Enforcement\EnforcementService;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\FlowFailed;
use SineMacula\Laravel\Sso\Events\HandoffRedeemed;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\HandoffCode;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Models\HandoffCode as StoredCode;
use SineMacula\Laravel\Sso\Sessions\Provenance;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken;
use Tests\Concerns\MigratesSso;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Mfa\Pending\CountsAdditionalFactors;
use Tests\Fixtures\Mfa\Pending\RequiresAdditionalVerification;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Resolvers\OpenTenancy;
use Tests\Fixtures\Sso\AcceptsTheProvidersContext;
use Tests\Fixtures\Sso\Handoff;
use Tests\Fixtures\Sso\Redemptions;
use Tests\TestCase;

/**
 * Integration tests for redeeming a `sign_in` handoff code.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SignInRedemption::class)]
#[CoversClass(ExternalResults::class)]
#[CoversClass(ClientTranslator::class)]
final class SignInRedemptionTest extends TestCase
{
    use MigratesSso, RunsAtIsolationLevels, RunsSsoFlows, SignsInPeople;

    /** @var string A verifier of the right shape that answers no challenge. */
    private const string WRONG_VERIFIER = 'not-the-verifier-the-client-kept-0123456789';

    /** @var string The format a whole-second instant is compared in. */
    private const string SECOND = 'Y-m-d H:i:s';

    /** @var string The factor a pending session is completed with. */
    private const string FACTOR = 'factor-1';

    /** @var \ArrayObject<int, object> What SSO reported of each redemption, in order. */
    private \ArrayObject $reported;

    /**
     * Arrange SSO, and listen for what each redemption reports.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeSso();

        $reported       = new \ArrayObject;
        $this->reported = $reported;

        Event::listen([FlowFailed::class, HandoffRedeemed::class], static function (object $event) use ($reported): void {
            $reported->append($event);
        });
    }

    /**
     * A linked sign-in writes one session with SSO's provenance.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testALinkedSignInSignsThePersonIn(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person = $this->createPerson();
        $linked = $this->linkThroughFlow($person);

        $this->reported->exchangeArray([]);

        $answer = $this->redeem($this->handoff());

        self::assertInstanceOf(SignInResult::class, $answer);
        self::assertTrue($answer->isSignedIn());
        self::assertInstanceOf(Person::class, $answer->session?->identity);
        self::assertTrue($answer->session->identity->is($person));

        $provenance = DB::table('authentication_provenance')->where('session_id', self::keyOf($answer->session->record))->first();

        self::assertNotNull($provenance);
        self::assertSame($this->connectionId, $provenance->connection_id);
        self::assertSame(self::TENANT, $provenance->tenant_id);
        self::assertSame($linked->linkId, $provenance->link_id);

        $context = json_decode((string) $provenance->provider_context, true, flags: JSON_THROW_ON_ERROR);

        self::assertIsArray($context);
        self::assertEqualsCanonicalizing(Provenance::STORED_KEYS, array_keys($context));
        self::assertSame(Provenance::restore($context)->toArray(), $context);
        self::assertSame($this->connectionId, $context['connection_id']);
        self::assertSame(self::TENANT, $context['tenant_id']);
        self::assertSame('oidc', $context['protocol']);
        self::assertSame($linked->linkId, $context['link_id']);
        self::assertSame(1, DB::table('authentication_sessions')->count());
        self::assertSame([HandoffRedeemed::class], $this->reportedEvents());

        $event = $this->reported[0];

        self::assertInstanceOf(HandoffRedeemed::class, $event);
        self::assertSame([self::CLIENT_IP, self::CLIENT_AGENT], [$event->context->ip, $event->context->userAgent]);
    }

    /**
     * A refusal by SSO commits and spends the code.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testARefusalBySsoCommitsAndSpendsTheCode(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $this->linkThroughFlow($this->createPerson());
        $this->reported->exchangeArray([]);

        $handoff  = $this->handoff();
        $refused  = $this->redeem(new Handoff($handoff->code, self::WRONG_VERIFIER, $handoff->reference));
        $replayed = $this->redeem($handoff);

        self::assertInstanceOf(RedemptionResult::class, $refused);
        self::assertSame(FailureReason::VERIFIER_MISMATCH, $refused->reason);
        self::assertInstanceOf(RedemptionResult::class, $replayed);
        self::assertSame(FailureReason::REPLAYED, $replayed->reason);
        self::assertSame(0, DB::table('authentication_sessions')->count());
        self::assertSame([FlowFailed::class, FlowFailed::class], $this->reportedEvents());
    }

    /**
     * A refusal by authentication rolls back and leaves the code unspent.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testARefusalByAuthenticationRollsBackAndLeavesTheCodeUnspent(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $this->linkThroughFlow($this->createPerson());
        $this->reported->exchangeArray([]);

        $handoff = $this->handoff();

        $this->allowExternalSignIn(false);

        $refusal = self::thrownBy(fn (): mixed => $this->redeem($handoff));

        self::assertInstanceOf(ExternalSignInRefusedException::class, $refusal);
        self::assertSame(AuthenticationFailure::METHOD_NOT_ALLOWED, $refusal->result->reason);
        self::assertSame(0, DB::table('authentication_sessions')->count());
        self::assertSame([], $this->reportedEvents());
        self::assertFalse($this->hasCompletedASignIn());

        $this->allowExternalSignIn(true);

        $answer = $this->redeem($handoff);

        self::assertInstanceOf(SignInResult::class, $answer);
        self::assertTrue($answer->isSignedIn());
        self::assertSame([HandoffRedeemed::class], $this->reportedEvents());
        self::assertTrue($this->hasCompletedASignIn());
    }

    /**
     * A session write that throws rolls the whole redemption back.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testASessionWriteThatThrowsLeavesTheCodeUnspentAndNoSignInAcknowledged(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $this->linkThroughFlow($this->createPerson());
        $this->reported->exchangeArray([]);

        $handoff = $this->handoff();
        $failing = new \ArrayObject([true]);

        self::assertFalse($this->hasCompletedASignIn());

        Session::creating(static function () use ($failing): void {
            if ($failing[0] === true) {
                throw new \RuntimeException('The session could not be written.');
            }
        });

        $thrown = self::thrownBy(fn (): mixed => $this->redeem($handoff));

        self::assertInstanceOf(\RuntimeException::class, $thrown);
        self::assertSame('The session could not be written.', $thrown->getMessage());
        self::assertSame(0, DB::table('authentication_sessions')->count());
        self::assertSame(0, DB::table('authentication_provenance')->count());
        self::assertFalse($this->hasCompletedASignIn());
        self::assertSame([], $this->reportedEvents());

        $failing[0] = false;

        $answer = $this->redeem($handoff);

        self::assertInstanceOf(SignInResult::class, $answer);
        self::assertTrue($answer->isSignedIn());
        self::assertTrue($this->hasCompletedASignIn());
        self::assertSame([HandoffRedeemed::class], $this->reportedEvents());
    }

    /**
     * The provenance names the enforcement version judged at redemption.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testTheProvenanceNamesTheEnforcementVersionJudgedAtRedemption(?string $level): void
    {
        self::runAtIsolationLevel($level);

        Config::set('sso.features.enforcement', true);

        $this->app?->instance(TenantResolver::class, new OpenTenancy);

        $this->linkThroughFlow($this->createPerson());

        self::assertInstanceOf(SignInResult::class, $this->redeem($this->handoff()));

        $enforcement = $this->app?->make(EnforcementService::class) ?? self::fail('The application has not booted.');
        $completed   = self::versionOf($enforcement->update(self::TENANT, true, [$this->connectionId], self::ssoClient()));
        $handoff     = $this->handoff();
        $judged      = self::versionOf($enforcement->update(self::TENANT, true, [$this->connectionId, $this->makeConnection()], self::ssoClient()));
        $answer      = $this->redeem($handoff);

        self::assertNotSame($completed, $judged);
        self::assertInstanceOf(SignInResult::class, $answer);
        self::assertTrue($answer->isSignedIn());

        $provenance = $this->provenanceOf($answer);

        self::assertSame($judged, $provenance->policy_version);
        self::assertSame($judged, self::contextOf($provenance)['enforcement_version']);
    }

    /**
     * The provider's session deadline caps the session.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testTheProvidersSessionDeadlineCapsTheSession(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person       = $this->createPerson();
        $connectionId = $this->makeSamlConnection();
        $link         = $this->samlHandoff($connectionId, Purpose::LINK, $person);

        self::assertTrue(Iam::links()->redeem($connectionId, $link->code, $link->verifier, self::client(), $this->requestCallerOf($person))->isRedeemed());

        $handoff  = $this->samlHandoff($connectionId);
        $notAfter = StoredCode::query()->where('code_digest', HandoffCode::fromString($handoff->code)->digest())->firstOrFail()->session_not_after;

        self::assertNotNull($notAfter);
        self::assertTrue($notAfter->isAfter(CarbonImmutable::now()->addHours(7)));

        $answer = Iam::signIns()->redeem(self::GUARD, $connectionId, $handoff->code, $handoff->verifier, new SignInContext(self::client()));

        self::assertInstanceOf(SignInResult::class, $answer);
        self::assertTrue($answer->isSignedIn());

        $provenance = $this->provenanceOf($answer);
        $context    = self::contextOf($provenance);
        $absolute   = DB::table('authentication_sessions')->where('id', self::keyOf($answer->session->record ?? self::fail('No session.')))->value('absolute_expires_at');

        self::assertSame('saml2', $context['protocol']);
        self::assertSame($notAfter->utc()->format(Provenance::INSTANT_FORMAT), $context['session_not_after']);
        self::assertSame($notAfter->utc()->format(self::SECOND), CarbonImmutable::parse((string) $provenance->provider_session_expires_at)->utc()->format(self::SECOND));
        self::assertIsString($absolute);
        self::assertSame($notAfter->utc()->format(self::SECOND), CarbonImmutable::parse($absolute)->utc()->format(self::SECOND));
    }

    /**
     * A raw context class outside the stored domain is kept as none.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testARawContextClassOutsideTheStoredDomainSignsInWithItNone(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $this->app?->instance(EvidencePolicy::class, new AcceptsTheProvidersContext);

        $this->linkThroughFlow($this->createPerson());

        $kept    = str_repeat('a', Provenance::MAX_CONTEXT_LENGTH);
        $outside = $kept . 'a';

        self::assertSame($kept, $this->acceptedContextOf($kept)['provider_acr']);

        $context = $this->acceptedContextOf($outside);

        self::assertArrayHasKey('provider_acr', $context);
        self::assertNull($context['provider_acr']);
        self::assertSame(['pwd'], $context['provider_amr']);
    }

    /**
     * An unlinked sign-in rolls back and leaves the code unspent.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAnUnlinkedSignInIsRolledBack(?string $level): void
    {
        self::runAtIsolationLevel($level);

        Config::set('sso.applications.' . self::GUARD . '.unlinked_handoffs', true);

        $handoff = $this->handoff();

        foreach ([1, 2] as $attempt) {

            $unlinked = self::thrownBy(fn (): mixed => $this->redeem($handoff));

            self::assertInstanceOf(UnlinkedSignInException::class, $unlinked, 'Attempt ' . $attempt);
            self::assertSame(self::GUARD, $unlinked->application);
            self::assertSame($this->connectionId, $unlinked->connectionId);
        }

        self::assertSame(0, DB::table('authentication_sessions')->count());
        self::assertSame([], $this->reportedEvents());
    }

    /**
     * A pending sign-in commits and keeps its provenance.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAPendingSignInCommits(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $this->app?->instance(AdditionalFactorPolicy::class, new RequiresAdditionalVerification);
        $this->app?->instance(RequirementCheck::class, new CountsAdditionalFactors(1));

        $person = $this->createPerson();
        $linked = $this->linkThroughFlow($person);

        $this->reported->exchangeArray([]);

        $answer = $this->redeem($this->handoff());

        self::assertInstanceOf(SignInResult::class, $answer);
        self::assertTrue($answer->isPending());
        self::assertNotNull($answer->credential);
        self::assertNotNull($answer->pending);
        self::assertSame($linked->linkId, DB::table('authentication_provenance')->value('link_id'));
        self::assertSame([HandoffRedeemed::class], $this->reportedEvents());

        $written = self::provenanceRows();
        $proof   = new ProofResult(
            ProofKind::ADDITIONAL_FACTOR,
            'totp',
            new Channel(ChannelKind::AUTHENTICATOR_APP, self::FACTOR),
            self::FACTOR,
            new ObservedProperties,
            new Evaluation(true, true),
            ['otp'],
            CarbonImmutable::now(),
            new ProofBinding($person, self::GUARD, $answer->pending->id, ProofPurpose::SIGN_IN),
        );

        $active = $this->sessions()->satisfy($answer->credential, $proof, self::client());

        self::assertTrue($active->isSignedIn());
        self::assertSame($written, self::provenanceRows(), 'Activation rewrote the provenance.');

        $refreshed = $this->sessions()->refresh(PresentedRefreshToken::fromBody($active->session?->tokens->refreshToken ?? self::fail('No refresh token.')), self::client());

        self::assertFalse($refreshed->isFailed());
        self::assertSame($written, self::provenanceRows(), 'A refresh rewrote the provenance.');

        $rotated  = $refreshed->session?->tokens->refreshToken ?? self::fail('No refresh token.');
        $switched = $this->sessions()->switchTo(PresentedRefreshToken::fromBody($rotated), SwitchTarget::principal($person), self::client());

        self::assertFalse($switched->isFailed());
        self::assertSame($written, self::provenanceRows(), 'A switch rewrote the provenance.');
    }

    /**
     * An application that is no session guard leaves the code untouched.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnApplicationThatIsNoSessionGuardThrowsBeforeTheCodeIsTouched(): void
    {
        $this->linkThroughFlow($this->createPerson());
        $this->reported->exchangeArray([]);

        $handoff    = $this->handoff();
        $unresolved = self::thrownBy(fn (): mixed => Iam::signIns()->redeem('web', $this->connectionId, $handoff->code, $handoff->verifier, new SignInContext(self::client())));

        self::assertInstanceOf(UnresolvedReferenceException::class, $unresolved);
        self::assertSame(ReferenceKind::GUARD, $unresolved->kind);
        self::assertSame([], $this->reportedEvents());
        self::assertInstanceOf(SignInResult::class, $this->redeem($handoff));
    }

    /**
     * Inside the caller's transaction the redemption commits with it.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testARedemptionInsideTheCallersTransactionCommitsWithIt(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $this->linkThroughFlow($this->createPerson());

        $handoff = $this->handoff();
        $answer  = Iam::transaction(fn (): mixed => $this->redeem($handoff));

        self::assertInstanceOf(SignInResult::class, $answer);
        self::assertTrue($answer->isSignedIn());
        self::assertSame(1, DB::table('authentication_sessions')->count());
    }

    /**
     * The admitted redemption is forgotten as the redemption starts and ends.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheAdmittedRedemptionIsTheRedemptionsAlone(): void
    {
        $this->linkThroughFlow($this->createPerson());

        $admitted = $this->app?->make(AdmittedRedemptions::class);

        self::assertInstanceOf(AdmittedRedemptions::class, $admitted);

        $admitted->record(Redemptions::signIn(), Redemptions::client());

        self::assertInstanceOf(SignInResult::class, $this->redeem($this->handoff()));
        self::assertNull($admitted->matching($this->connectionId, (string) $this->provider?->issuer, 'fake-subject', null));
        self::assertNull($admitted->matching(Redemptions::CONNECTION, Redemptions::ISSUER, Redemptions::SUBJECT, Redemptions::NAME_ID_FORMAT));
    }

    /**
     * Sign in with the raw context class given, and answer the provider
     * context.
     *
     * @param  string  $raw
     * @return array<array-key, mixed>
     *
     * @throws \Throwable
     */
    private function acceptedContextOf(string $raw): array
    {
        $answer = $this->redeem($this->handoff(tailor: static fn (FakeIdToken $token): FakeIdToken => $token->with('acr', $raw)->with('amr', ['pwd'])));

        self::assertInstanceOf(SignInResult::class, $answer);
        self::assertTrue($answer->isSignedIn());

        return self::contextOf($this->provenanceOf($answer));
    }

    /**
     * Redeem the handoff for the guard through the connection.
     *
     * @param  \Tests\Fixtures\Sso\Handoff  $handoff
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult|\SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     *
     * @throws \Throwable
     */
    private function redeem(Handoff $handoff): RedemptionResult|SignInResult
    {
        return Iam::signIns()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, new SignInContext(self::client()));
    }

    /**
     * Whether the connection has acknowledged a completed sign-in.
     *
     * @return bool
     */
    private function hasCompletedASignIn(): bool
    {
        return (bool) DB::table('sso_connections')->where('id', $this->connectionId)->value('has_completed_sign_in');
    }

    /**
     * The provenance written with the session the sign-in established.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInResult  $answer
     * @return \stdClass
     */
    private function provenanceOf(SignInResult $answer): \stdClass
    {
        $record = $answer->session->record ?? self::fail('The sign-in established no session.');

        return DB::table('authentication_provenance')->where('session_id', self::keyOf($record))->first() ?? self::fail('The session has no provenance.');
    }

    /**
     * The provenance's provider context, decoded.
     *
     * @param  \stdClass  $provenance
     * @return array<array-key, mixed>
     */
    private static function contextOf(\stdClass $provenance): array
    {
        $context = json_decode((string) ($provenance->provider_context ?? ''), true, flags: JSON_THROW_ON_ERROR);

        return is_array($context) ? $context : self::fail('The provenance has no provider context.');
    }

    /**
     * Every provenance row, each as its columns, in the order of its session.
     *
     * @return list<array<string, mixed>>
     */
    private static function provenanceRows(): array
    {
        return array_values(array_map(static fn (object $row): array => (array) $row, DB::table('authentication_provenance')->orderBy('session_id')->get()->all()));
    }

    /**
     * The version the enforcement change stored, failing unless it changed.
     *
     * @param  \SineMacula\Laravel\Sso\Enforcement\EnforcementResult  $result
     * @return string
     */
    private static function versionOf(EnforcementResult $result): string
    {
        self::assertTrue($result->isChanged(), sprintf('The enforcement did not change: [%s].', $result->reason->value ?? $result->status->value));

        return $result->enforcement->version ?? self::fail('The enforcement has no version.');
    }

    /**
     * Allow or stop allowing external sign-in on the guard.
     *
     * @param  bool  $allowed
     * @return void
     */
    private function allowExternalSignIn(bool $allowed): void
    {
        Config::set('auth.guards.' . self::GUARD . '.application.methods', $allowed ? ['password', 'external_provider'] : ['password']);

        $this->app?->make('auth')->forgetGuards();
    }

    /**
     * What the call threw, failing when it threw nothing.
     *
     * @param  \Closure(): mixed  $call
     * @return \Throwable
     */
    private static function thrownBy(\Closure $call): \Throwable
    {
        try {
            $call();
        } catch (\Throwable $thrown) {
            return $thrown;
        }

        self::fail('The call threw nothing.');
    }

    /**
     * The class of each event reported, in order.
     *
     * @return list<class-string>
     */
    private function reportedEvents(): array
    {
        return array_values(array_map(static fn (object $event): string => $event::class, $this->reported->getArrayCopy()));
    }
}
