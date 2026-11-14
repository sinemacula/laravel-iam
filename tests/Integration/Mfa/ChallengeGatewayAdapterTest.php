<?php

declare(strict_types = 1);

namespace Tests\Integration\Mfa;

use Carbon\CarbonImmutable;
use Illuminate\Auth\AuthManager as LaravelAuthManager;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Models\OneTimeCode;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind as AuthenticationChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose as AuthenticationPurpose;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\ChallengeGatewayAdapter;
use SineMacula\Laravel\Iam\Mfa\CurrentSession;
use SineMacula\Laravel\Iam\Mfa\FactorCodeCallers;
use SineMacula\Laravel\Iam\Mfa\Translation\CodeTranslator;
use SineMacula\Laravel\Mfa\Codes\SendResult;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Context\ClientContext as MfaClientContext;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Events\LockoutApplied;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Enrollment;
use SineMacula\Laravel\Mfa\Models\Factor as FactorModel;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\ChallengeGatewayTests;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Concerns\BindsStrayRequests;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Mfa\Codes\Concerns\ArrangesDeliveredFactors;
use Tests\Fixtures\Mfa\Codes\Concerns\DeliversFactorCodes;
use Tests\Fixtures\Mfa\Codes\DetachedFactor;
use Tests\Fixtures\Mfa\Codes\RecordingCodeDriver;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * Integration tests for MFA's challenge gateway over factor codes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ChallengeGatewayAdapter::class)]
#[CoversClass(CodeTranslator::class)]
final class ChallengeGatewayAdapterTest extends TestCase
{
    use ArrangesDeliveredFactors, BindsStrayRequests, ChallengeGatewayTests, DeliversFactorCodes, MigratesMembers, RunsAtIsolationLevels, SignsInPeople;

    /** @var string A challenge id in the form `laravel-authentication` issues, naming no challenge. */
    private const string UNKNOWN_CHALLENGE = '00000000-0000-4000-8000-000000000000';

    /** @var string A challenge id that is not in the form `laravel-authentication` issues. */
    private const string MALFORMED_CHALLENGE = 'not-a-challenge';

    /** @var string A number no factor of the kit's person's sends to. */
    private const string OTHER_PHONE = '+447700900999';

    /** @var string What the tests roll their own transaction back with. */
    private const string ROLLED_BACK = 'The transaction rolls back.';

    /** @var ?\Tests\Fixtures\Models\Person The person whose factor the kit challenges. */
    private ?Person $person = null;

    /** @var ?(\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession) The session the kit's challenges are bound to. */
    private (EloquentSession&Model)|null $session = null;

    /** @var ?\SineMacula\Laravel\Mfa\Models\Factor The factor the kit challenges. */
    private ?FactorModel $factor = null;

    /**
     * Fake the delivery of factor codes.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->fakeFactorCodeDelivery();
    }

    /**
     * A code is issued and delivered by `laravel-authentication`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACodeIsSentThroughAuthentication(): void
    {
        $sent = $this->challengeGateway()->send($this->challengeCaller(), $this->challengedFactor(), $this->challengeBinding());

        self::assertTrue($sent->wasSent());
        self::assertNotNull($sent->challengeId);
        self::assertSame(1, $this->queuedDeliveries());

        $messages = $this->deliverFactorCodes();

        self::assertCount(1, $messages);
        self::assertSame(CodePurpose::MFA, $messages[0]->purpose);
        self::assertSame('sms', $messages[0]->type);
        self::assertSame(self::DELIVERED_PHONE, $messages[0]->identifier);
        self::assertSame(self::GUARD, $messages[0]->guard);
        self::assertEquals($messages[0]->expiresAt, $sent->expiresAt);
        self::assertSame($this->person()->getKey(), $messages[0]->identity->getAuthIdentifier());
        self::assertSame($messages, $this->codeSender()->sent(), 'MFA\'s own senders deliver nothing.');
    }

    /**
     * A step-up is proved end to end with a code through the gateway.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStepUpIsProvedWithACodeThroughAuthentication(): void
    {
        $factor = $this->challengedFactor();
        $sent   = Mfa::sendCode(self::servedCaller(), $factor->id, Purpose::STEP_UP);

        self::assertTrue($sent->wasSent(), (string) $sent->reason?->value);

        $code     = $this->deliveredCodeTo(self::DELIVERED_PHONE);
        $verified = Mfa::verify(self::servedCaller(), Submission::challenge($factor->id, (string) $sent->challengeId, $code), Purpose::STEP_UP);

        self::assertTrue($verified->isVerified(), (string) $verified->reason?->value);

        $proof = $this->proofsOf($this->personsSession())[0];

        self::assertSame(AuthenticationPurpose::STEP_UP, $proof->purpose);
        self::assertSame($factor->id, $proof->factor);
        self::assertSame(AuthenticationChannelKind::SMS, $proof->channel->kind);
        self::assertSame(self::DELIVERED_PHONE, $proof->channel->reference);
        self::assertCount(1, $this->codeSender()->sent(), 'MFA\'s own senders deliver nothing.');
    }

    /**
     * A pending sign-in is completed with a code as the pending caller's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPendingSignInIsCompletedWithACodeThroughAuthentication(): void
    {
        $person = $this->createPerson();
        $factor = $this->deliveredFactor($person);
        $result = $this->attemptSignIn($person);

        self::assertTrue($result->isPending(), (string) $result->reason?->value);
        self::assertNotNull($result->credential);

        $caller = self::servedCaller(Request::create('/mfa/verify', 'POST', ['pending_credential' => $result->credential->reveal()]));

        $this->bindStrayRequest();

        $sent = Mfa::sendCode($caller, $factor->id, Purpose::SIGN_IN);

        self::assertNotNull($caller->pending);
        self::assertTrue($sent->wasSent(), (string) $sent->reason?->value);

        $verified = Mfa::verify($caller, Submission::challenge($factor->id, (string) $sent->challengeId, $this->deliveredCodeTo(self::DELIVERED_PHONE)), Purpose::SIGN_IN);

        self::assertTrue($verified->isVerified(), (string) $verified->reason?->value);

        $completion = $verified->completion();

        self::assertInstanceOf(SignInResult::class, $completion);
        self::assertTrue($completion->isSignedIn());
    }

    /**
     * The caller's client is handed on, never the bound request's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheCallersClientIsHandedOn(): void
    {
        $challenge = $this->sentChallenge();
        $code      = $this->deliveredCode($challenge);
        $factor    = $this->challengedFactor();
        $events    = [];

        FactorModel::query()->whereKey($factor->id)->update([$factor->getLockedUntilName() => CarbonImmutable::now()->addMinutes(10)]);

        $this->bindStrayRequest();

        Event::listen(AuthenticationFailed::class, static function (AuthenticationFailed $event) use (&$events): void {
            $events[] = $event;
        });

        self::assertSame(FailureReason::LOCKED, $this->challengeGateway()->send($this->challengeCaller(), $factor, $this->challengeBinding())->reason);
        self::assertSame(FailureReason::LOCKED, $this->challengeGateway()->verify($this->challengeCaller(), $factor, $this->challengeBinding(), $challenge, $code)->reason);
        self::assertCount(2, $events);

        foreach ($events as $event) {
            self::assertSame([self::CLIENT_IP, self::CLIENT_AGENT], [$event->context->client->ip, $event->context->client->userAgent]);
        }
    }

    /**
     * A request bound in the container never reaches a code.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABoundRequestNeverReachesTheCode(): void
    {
        config()->set('mfa.attempts.factor_limit', 1);

        $factor  = $this->challengedFactor();
        $pending = $this->attemptSignIn($this->person());
        $events  = [];

        self::assertTrue($pending->isPending(), (string) $pending->reason?->value);
        self::assertNotNull($pending->credential);

        $this->bindStrayRequest(['pending_credential' => $pending->credential->reveal()]);

        Event::listen(LockoutApplied::class, static function (LockoutApplied $event) use (&$events): void {
            $events[] = $event;
        });

        $challenge = $this->sentChallenge();
        $outcome   = $this->challengeGateway()->verify($this->challengeCaller(), $factor, $this->challengeBinding(), $challenge, self::wrong($this->deliveredCode($challenge)));

        self::assertSame(FailureReason::INVALID_CODE, $outcome->reason);
        self::assertTrue($outcome->counted);
        self::assertCount(1, $events);
        self::assertSame([self::CLIENT_IP, self::CLIENT_AGENT], [$events[0]->context['ip'], $events[0]->context['user_agent']]);
    }

    /**
     * A caller that is nobody is refused by throwing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACallerThatIsNobodyIsRefusedByThrowing(): void
    {
        $challenge = $this->sentChallenge();
        $code      = $this->deliveredCode($challenge);
        $factor    = $this->challengedFactor();
        $binding   = $this->challengeBinding();
        $nobody    = CallerContext::nobody(self::GUARD, new MfaClientContext(self::CLIENT_IP, self::CLIENT_AGENT));

        $calls = [
            fn (): mixed => $this->challengeGateway()->send($nobody, $factor, $binding),
            fn (): mixed => $this->challengeGateway()->verify($nobody, $factor, $binding, $challenge, $code),
        ];

        foreach ($calls as $call) {
            $refusal = self::thrownBy($call);

            self::assertInstanceOf(\InvalidArgumentException::class, $refusal);
            self::assertSame('Challenge counters are kept for an identity, and the caller is nobody.', $refusal->getMessage());
            self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel());
        }

        self::assertSame(1, OneTimeCode::query()->count());
        self::assertSame(0, $this->queuedDeliveries());
        self::assertSame(0, $this->failures());
        self::assertTrue($this->challengeGateway()->verify($this->challengeCaller(), $factor, $binding, $challenge, $code)->hasPassed());
    }

    /**
     * A binding of another application is refused as `not_accepted`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABindingOfAnotherApplicationThanTheCallersIsRefusedByThrowing(): void
    {
        $challenge = $this->sentChallenge();
        $code      = $this->deliveredCode($challenge);
        $factor    = $this->challengedFactor();
        $binding   = $this->challengeBinding();
        $elsewhere = self::callerOf($this->person(), 'admin');

        $calls = [
            fn (): mixed => $this->challengeGateway()->send($elsewhere, $factor, $binding),
            fn (): mixed => $this->challengeGateway()->verify($elsewhere, $factor, $binding, $challenge, $code),
        ];

        foreach ($calls as $call) {
            $refusal = self::thrownBy($call);

            self::assertInstanceOf(OperationRefusedException::class, $refusal);
            self::assertSame(FailureReason::NOT_ACCEPTED, $refusal->reason);
            self::assertSame(ChallengeGatewayAdapter::ANOTHER_APPLICATION, $refusal->getMessage());
            self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel());
        }

        self::assertSame(1, OneTimeCode::query()->count());
        self::assertSame(0, $this->queuedDeliveries());
        self::assertSame(0, $this->failures());
        self::assertTrue($this->challengeGateway()->verify($this->challengeCaller(), $factor, $binding, $challenge, $code)->hasPassed());
    }

    /**
     * A caller of another identity than the binding's is judged as that caller.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACallerOfAnotherIdentityIsJudgedAsThatCaller(): void
    {
        $challenge = $this->sentChallenge();
        $code      = $this->deliveredCode($challenge);
        $factor    = $this->challengedFactor();
        $binding   = $this->challengeBinding();
        $stranger  = self::callerOf($this->createPerson());

        self::assertSame(FailureReason::NOT_FOUND, $this->challengeGateway()->send($stranger, $factor, $binding)->reason);

        $outcome = $this->challengeGateway()->verify($stranger, $factor, $binding, $challenge, self::wrong($code));

        self::assertSame(FailureReason::NOT_FOUND, $outcome->reason);
        self::assertFalse($outcome->counted);
        self::assertSame(1, OneTimeCode::query()->count());
        self::assertSame(0, $this->failures());
        self::assertTrue($this->challengeGateway()->verify($this->challengeCaller(), $factor, $binding, $challenge, $code)->hasPassed());
    }

    /**
     * An SMS factor is enrolled end to end with a code.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnEnrolmentIsConfirmedWithACodeThroughAuthentication(): void
    {
        $person          = $this->person();
        $reauthenticated = $this->sessions()->reauthenticate($this->personsSession(), 'password', ['email' => $person->email, 'password' => self::PASSWORD], self::client());

        self::assertTrue($reauthenticated->isIssued());

        $start = Mfa::startEnrollment(self::servedCaller(), EnrollmentRequest::delivered('sms', self::OTHER_PHONE));

        self::assertTrue($start->hasStarted(), (string) $start->reason?->value);
        self::assertNotNull($start->grant);

        $messages = $this->deliverFactorCodes();

        self::assertCount(1, $messages);
        self::assertSame(CodePurpose::ENROLLMENT, $messages[0]->purpose);

        $confirmation = Mfa::confirmEnrollment(self::servedCaller(), $start->grant, $messages[0]->code->reveal());

        self::assertTrue($confirmation->isConfirmed(), (string) $confirmation->reason?->value);
        self::assertTrue(FactorModel::query()->where('destination', self::OTHER_PHONE)->sole()->isConfirmed());
    }

    /**
     * A wrong code fails as invalid and is counted against the factor.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAWrongCodeIsCountedAgainstTheFactor(): void
    {
        $challenge = $this->sentChallenge();
        $wrong     = self::wrong($this->deliveredCode($challenge));
        $outcome   = $this->challengeGateway()->verify($this->challengeCaller(), $this->challengedFactor(), $this->challengeBinding(), $challenge, $wrong);

        self::assertSame(FailureReason::INVALID_CODE, $outcome->reason);
        self::assertSame(CodeTranslator::INVALID, $outcome->detail);
        self::assertTrue($outcome->counted);
        self::assertSame(1, $this->failures());
    }

    /**
     * A used code is refused as replayed and counted against nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAUsedCodeIsRefusedAsReplayed(): void
    {
        $challenge = $this->sentChallenge();
        $code      = $this->deliveredCode($challenge);

        self::assertTrue($this->challengeGateway()->verify($this->challengeCaller(), $this->challengedFactor(), $this->challengeBinding(), $challenge, $code)->hasPassed());

        $again = $this->challengeGateway()->verify($this->challengeCaller(), $this->challengedFactor(), $this->challengeBinding(), $challenge, $code);

        self::assertSame(FailureReason::REPLAYED, $again->reason);
        self::assertSame(CodeTranslator::REPLAYED, $again->detail);
        self::assertFalse($again->counted);
        self::assertSame(0, $this->failures());
    }

    /**
     * Another code at a used challenge is refused as invalid and counted
     * against nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnotherCodeAtAUsedChallengeIsRefusedAsInvalid(): void
    {
        $challenge = $this->sentChallenge();
        $code      = $this->deliveredCode($challenge);

        self::assertTrue($this->challengeGateway()->verify($this->challengeCaller(), $this->challengedFactor(), $this->challengeBinding(), $challenge, $code)->hasPassed());

        $again = $this->challengeGateway()->verify($this->challengeCaller(), $this->challengedFactor(), $this->challengeBinding(), $challenge, self::wrong($code));

        self::assertSame(FailureReason::INVALID_CODE, $again->reason);
        self::assertSame(CodeTranslator::USED, $again->detail);
        self::assertFalse($again->counted);
        self::assertSame(0, $this->failures());
    }

    /**
     * A malformed challenge id is not found, and counted against nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMalformedChallengeIsNotFound(): void
    {
        $outcome = $this->challengeGateway()->verify($this->challengeCaller(), $this->challengedFactor(), $this->challengeBinding(), 'unknown-challenge', '000000');

        self::assertSame(FailureReason::NOT_FOUND, $outcome->reason);
        self::assertSame(CodeTranslator::NOT_FOUND, $outcome->detail);
        self::assertFalse($outcome->counted);
        self::assertSame(0, $this->failures());
    }

    /**
     * A well-formed challenge id naming no challenge is not found.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnknownChallengeIsNotFound(): void
    {
        $code    = $this->deliveredCode($this->sentChallenge());
        $outcome = $this->challengeGateway()->verify($this->challengeCaller(), $this->challengedFactor(), $this->challengeBinding(), self::UNKNOWN_CHALLENGE, $code);

        self::assertSame(FailureReason::NOT_FOUND, $outcome->reason);
        self::assertFalse($outcome->counted);
        self::assertSame(0, $this->failures());
    }

    /**
     * MFA's IP throttle never counts a challenge that is not found or used.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testMfasIpThrottleNeverCountsAChallengeNotFoundOrUsed(): void
    {
        config()->set('mfa.attempts.ip_limit', 1);

        $factor = $this->challengedFactor();
        $sent   = Mfa::sendCode(self::servedCaller(), $factor->id, Purpose::STEP_UP);

        self::assertTrue($sent->wasSent(), (string) $sent->reason?->value);

        $code = $this->deliveredCodeTo(self::DELIVERED_PHONE);

        foreach ([self::UNKNOWN_CHALLENGE, self::UNKNOWN_CHALLENGE, self::UNKNOWN_CHALLENGE] as $challenge) {
            self::assertSame(FailureReason::NOT_FOUND, Mfa::verify(self::servedCaller(), Submission::challenge($factor->id, $challenge, $code), Purpose::STEP_UP)->reason);
        }

        $verified = Mfa::verify(self::servedCaller(), Submission::challenge($factor->id, (string) $sent->challengeId, $code), Purpose::STEP_UP);

        self::assertTrue($verified->isVerified(), (string) $verified->reason?->value);

        $replayed = Mfa::verify(self::servedCaller(), Submission::challenge($factor->id, (string) $sent->challengeId, $code), Purpose::STEP_UP);
        $used     = Mfa::verify(self::servedCaller(), Submission::challenge($factor->id, (string) $sent->challengeId, self::wrong($code)), Purpose::STEP_UP);

        self::assertSame([FailureReason::REPLAYED, FailureReason::INVALID_CODE], [$replayed->reason, $used->reason]);
    }

    /**
     * The IP limit bounds checks of a challenge that is not found.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAuthenticationsIpLimitBoundsChecksOfAChallengeNotFound(): void
    {
        config()->set('authentication.rate_limits.factor_code.per_ip', ['max' => 1, 'decay_seconds' => 300]);

        $factor = $this->challengedFactor();
        $sent   = Mfa::sendCode(self::servedCaller(), $factor->id, Purpose::STEP_UP);

        self::assertTrue($sent->wasSent(), (string) $sent->reason?->value);

        $code    = $this->deliveredCodeTo(self::DELIVERED_PHONE);
        $reasons = [];

        for ($check = 0; $check < 3; $check++) {
            $reasons[] = Mfa::verify(self::servedCaller(), Submission::challenge($factor->id, self::UNKNOWN_CHALLENGE, $code), Purpose::STEP_UP)->reason;
        }

        self::assertSame([FailureReason::NOT_FOUND, FailureReason::LOCKED, FailureReason::LOCKED], $reasons);
        self::assertSame(0, $this->failures());
    }

    /**
     * The IP limit bounds checks of a malformed challenge id.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAuthenticationsIpLimitBoundsChecksOfAMalformedChallenge(): void
    {
        config()->set('authentication.rate_limits.factor_code.per_ip', ['max' => 1, 'decay_seconds' => 300]);

        $factor = $this->challengedFactor();
        $sent   = Mfa::sendCode(self::servedCaller(), $factor->id, Purpose::STEP_UP);

        self::assertTrue($sent->wasSent(), (string) $sent->reason?->value);

        $code    = $this->deliveredCodeTo(self::DELIVERED_PHONE);
        $reasons = [];

        for ($check = 0; $check < 3; $check++) {
            $reasons[] = Mfa::verify(self::servedCaller(), Submission::challenge($factor->id, self::MALFORMED_CHALLENGE, $code), Purpose::STEP_UP)->reason;
        }

        self::assertSame([FailureReason::NOT_FOUND, FailureReason::LOCKED, FailureReason::LOCKED], $reasons);
        self::assertSame(0, $this->failures());

        $real = Mfa::verify(self::servedCaller(), Submission::challenge($factor->id, (string) $sent->challengeId, $code), Purpose::STEP_UP);

        self::assertSame(FailureReason::LOCKED, $real->reason);
    }

    /**
     * A code at a used enrolment challenge is counted against the enrolment.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACodeAtAUsedEnrolmentChallengeIsCountedAgainstTheEnrolment(): void
    {
        $person          = $this->person();
        $reauthenticated = $this->sessions()->reauthenticate($this->personsSession(), 'password', ['email' => $person->email, 'password' => self::PASSWORD], self::client());

        self::assertTrue($reauthenticated->isIssued());

        $start = Mfa::startEnrollment(self::servedCaller(), EnrollmentRequest::delivered('sms', self::OTHER_PHONE));

        self::assertTrue($start->hasStarted(), (string) $start->reason?->value);
        self::assertNotNull($start->grant);

        $messages = $this->deliverFactorCodes();

        self::assertCount(1, $messages);

        OneTimeCode::query()->sole()->forceFill(['consumed_at' => CarbonImmutable::now()])->save();

        $confirmation = Mfa::confirmEnrollment(self::servedCaller(), $start->grant, self::wrong($messages[0]->code->reveal()));

        self::assertSame(FailureReason::INVALID_CODE, $confirmation->reason);
        self::assertSame(1, Enrollment::query()->sole()->attempts);
    }

    /**
     * An expired code is refused as expired and counted against nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnExpiredCodeIsRefusedAsExpired(): void
    {
        $challenge = $this->sentChallenge();
        $code      = $this->deliveredCode($challenge);

        $this->travel(601)->seconds();

        $outcome = $this->challengeGateway()->verify($this->challengeCaller(), $this->challengedFactor(), $this->challengeBinding(), $challenge, $code);

        self::assertSame(FailureReason::EXPIRED, $outcome->reason);
        self::assertSame(CodeTranslator::EXPIRED, $outcome->detail);
        self::assertFalse($outcome->counted);
        self::assertSame(0, $this->failures());
    }

    /**
     * A locked factor is sent no code and refused as locked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALockedFactorIsRefusedAsLocked(): void
    {
        $this->freezeSecond();

        $challenge = $this->sentChallenge();
        $code      = $this->deliveredCode($challenge);
        $factor    = $this->challengedFactor();
        $until     = CarbonImmutable::now()->startOfSecond()->addMinutes(10);

        FactorModel::query()->whereKey($factor->id)->update([$factor->getLockedUntilName() => $until]);

        $sent    = $this->challengeGateway()->send($this->challengeCaller(), $factor, $this->challengeBinding());
        $outcome = $this->challengeGateway()->verify($this->challengeCaller(), $factor, $this->challengeBinding(), $challenge, $code);

        self::assertSame(FailureReason::LOCKED, $sent->reason);
        self::assertSame(600, $sent->retryAfter);
        self::assertSame(0, $this->queuedDeliveries());
        self::assertSame(FailureReason::LOCKED, $outcome->reason);
        self::assertSame(CodeTranslator::LOCKED, $outcome->detail);
        self::assertFalse($outcome->counted);
        self::assertEquals($until, $outcome->lockedUntil);
    }

    /**
     * A factor of a type no longer offered is refused for MFA's reason.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFactorOfATypeNoLongerOfferedIsRefusedForMfasReason(): void
    {
        $challenge = $this->sentChallenge();
        $code      = $this->deliveredCode($challenge);

        config()->set('mfa.applications.' . self::GUARD . '.types', ['totp']);

        $sent    = $this->challengeGateway()->send($this->challengeCaller(), $this->challengedFactor(), $this->challengeBinding());
        $outcome = $this->challengeGateway()->verify($this->challengeCaller(), $this->challengedFactor(), $this->challengeBinding(), $challenge, $code);

        self::assertSame(FailureReason::TYPE_NOT_ENABLED, $sent->reason);
        self::assertSame(FailureReason::TYPE_NOT_ENABLED, $outcome->reason);
        self::assertSame(CodeTranslator::REFUSED, $outcome->detail);
        self::assertFalse($outcome->counted);
    }

    /**
     * A code asked for again too soon is refused as sending capped.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACodeAskedForAgainTooSoonIsSendingCapped(): void
    {
        $this->freezeSecond();

        config()->set('authentication.codes.resend_cooldown_seconds', 60);

        $this->sentChallenge();

        $again = $this->challengeGateway()->send($this->challengeCaller(), $this->challengedFactor(), $this->challengeBinding());

        self::assertSame(FailureReason::SENDING_CAPPED, $again->reason);
        self::assertSame(60, $again->retryAfter);
        self::assertSame(1, $this->queuedDeliveries());
    }

    /**
     * Checks beyond the IP address's limit are refused as locked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testChecksBeyondTheIpAddresssLimitAreRefusedAsLocked(): void
    {
        config()->set('authentication.rate_limits.factor_code.per_ip', ['max' => 1, 'decay_seconds' => 300]);

        $challenge = $this->sentChallenge();
        $wrong     = self::wrong($this->deliveredCode($challenge));

        $this->challengeGateway()->verify($this->challengeCaller(), $this->challengedFactor(), $this->challengeBinding(), $challenge, $wrong);

        $outcome = $this->challengeGateway()->verify($this->challengeCaller(), $this->challengedFactor(), $this->challengeBinding(), $challenge, $wrong);

        self::assertSame(FailureReason::LOCKED, $outcome->reason);
        self::assertSame(CodeTranslator::RATE_LIMITED, $outcome->detail);
        self::assertFalse($outcome->counted);
        self::assertNotNull($outcome->lockedUntil);
        self::assertTrue($outcome->lockedUntil->isFuture());
        self::assertSame(1, $this->failures());
    }

    /**
     * A factor of another identity is not found.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFactorOfAnotherIdentityIsNotFound(): void
    {
        $this->person();

        $factor  = $this->deliveredFactor($this->createPerson(), 'sms', self::OTHER_PHONE);
        $sent    = $this->challengeGateway()->send($this->challengeCaller(), $factor, $this->challengeBinding());
        $outcome = $this->challengeGateway()->verify($this->challengeCaller(), $factor, $this->challengeBinding(), 'unknown-challenge', '000000');

        self::assertSame(FailureReason::NOT_FOUND, $sent->reason);
        self::assertSame(FailureReason::NOT_FOUND, $outcome->reason);
        self::assertSame(ChallengeGatewayAdapter::NOT_FOUND, $outcome->detail);
        self::assertFalse($outcome->counted);
        self::assertSame(0, $this->queuedDeliveries());
        self::assertSame(0, OneTimeCode::query()->count());
    }

    /**
     * A factor keeping no state of its own is not found.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFactorKeepingNoStateIsNotFound(): void
    {
        $factor = new DetachedFactor;

        self::assertSame(FailureReason::NOT_FOUND, $this->challengeGateway()->send($this->challengeCaller(), $factor, $this->challengeBinding())->reason);

        $checked = $this->challengeGateway()->verify($this->challengeCaller(), $factor, $this->challengeBinding(), 'unknown-challenge', '000000');

        self::assertSame(FailureReason::NOT_FOUND, $checked->reason);
        self::assertSame(0, OneTimeCode::query()->count());
    }

    /**
     * A reauthentication is refused as not accepted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReauthenticationIsNotAccepted(): void
    {
        $binding = $this->bindingOf($this->person(), Purpose::REAUTHENTICATE);
        $outcome = $this->challengeGateway()->verify($this->challengeCaller(), $this->challengedFactor(), $binding, 'unknown-challenge', '000000');

        self::assertSame(FailureReason::NOT_ACCEPTED, $this->challengeGateway()->send($this->challengeCaller(), $this->challengedFactor(), $binding)->reason);
        self::assertSame(FailureReason::NOT_ACCEPTED, $outcome->reason);
        self::assertSame(ChallengeGatewayAdapter::REAUTHENTICATION, $outcome->detail);
        self::assertSame(0, OneTimeCode::query()->count());
    }

    /**
     * Rows of `[factor type, channel kind]` for each channel a code goes by.
     *
     * @return iterable<string, array{0: string, 1: \SineMacula\Laravel\Mfa\Enums\ChannelKind}>
     */
    public static function provideCodeChannels(): iterable
    {
        yield 'sms' => ['sms', ChannelKind::SMS];

        yield 'email' => ['email', ChannelKind::EMAIL];
    }

    /**
     * An application's SMS or email driver goes through authentication.
     *
     * @param  string  $type
     * @param  \SineMacula\Laravel\Mfa\Enums\ChannelKind  $kind
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideCodeChannels')]
    public function testAnApplicationsSmsOrEmailDriverGoesThroughAuthentication(string $type, ChannelKind $kind): void
    {
        $driver = new RecordingCodeDriver($kind);

        Mfa::extend($type, static fn (): RecordingCodeDriver => $driver);

        $factor   = $this->deliveredFactor($this->person(), $type);
        $sent     = $this->challengeGateway()->send($this->challengeCaller(), $factor, $this->challengeBinding());
        $messages = $this->deliverFactorCodes();

        self::assertTrue($sent->wasSent(), (string) $sent->reason?->value);
        self::assertCount(1, $messages);
        self::assertSame($type, $messages[0]->type);
        self::assertSame(self::deliveredDestination($this->person(), $type), $messages[0]->identifier);
        self::assertSame([], $driver->messages());

        $outcome = $this->challengeGateway()->verify($this->challengeCaller(), $factor, $this->challengeBinding(), (string) $sent->challengeId, $messages[0]->code->reveal());

        self::assertTrue($outcome->hasPassed());
    }

    /**
     * A factor whose driver delivers by neither SMS nor email is not accepted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADriverOfAnotherChannelKindIsNotAccepted(): void
    {
        config()->set('mfa.applications.' . self::GUARD . '.types', ['totp', 'sms', 'email', 'push']);

        $driver = new RecordingCodeDriver(ChannelKind::EXTERNAL_PROVIDER);

        Mfa::extend('push', static fn (): RecordingCodeDriver => $driver);

        $factor  = $this->deliveredFactor($this->person(), 'push', 'device-token-1');
        $sent    = $this->challengeGateway()->send($this->challengeCaller(), $factor, $this->challengeBinding());
        $outcome = $this->challengeGateway()->verify($this->challengeCaller(), $factor, $this->challengeBinding(), self::UNKNOWN_CHALLENGE, '000000');

        self::assertSame(FailureReason::NOT_ACCEPTED, $sent->reason);
        self::assertSame(FailureReason::NOT_ACCEPTED, $outcome->reason);
        self::assertSame(ChallengeGatewayAdapter::NOT_A_CODE_CHANNEL, $outcome->detail);
        self::assertSame([], $driver->messages());
        self::assertSame(0, OneTimeCode::query()->count());
    }

    /**
     * An application that names no guard throws on send and check.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnApplicationThatIsNoGuardThrows(): void
    {
        $owner   = ProofOwner::of($this->person());
        $binding = new ProofBinding($owner->type, $owner->key, 'console', $this->signInReference($this->personsSession()), Purpose::STEP_UP);
        $caller  = self::callerOf($this->person(), 'console');

        $calls = [
            fn (): mixed => $this->challengeGateway()->send($caller, $this->challengedFactor(), $binding),
            fn (): mixed => $this->challengeGateway()->verify($caller, $this->challengedFactor(), $binding, 'unknown-challenge', '000000'),
        ];

        foreach ($calls as $call) {
            $refusal = self::thrownBy($call);

            self::assertInstanceOf(UnresolvedReferenceException::class, $refusal);
            self::assertSame(ReferenceKind::GUARD, $refusal->kind);
            self::assertSame('console', $refusal->application);
        }
    }

    /**
     * An authentication factory of another kind cannot resolve the guard.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAuthenticationFactoryOfAnotherKindThrows(): void
    {
        $app     = $this->app ?? self::fail('The application has not booted.');
        $gateway = new ChallengeGatewayAdapter(new LaravelAuthManager($app), $app->make(CurrentSession::class), $app->make(CodeTranslator::class), new FactorCodeCallers);
        $refusal = self::thrownBy(fn (): mixed => $gateway->send($this->challengeCaller(), $this->challengedFactor(), $this->challengeBinding()));

        self::assertInstanceOf(UnresolvedReferenceException::class, $refusal);
        self::assertSame(ReferenceKind::GUARD, $refusal->kind);
    }

    /**
     * A code sent inside the caller's transaction rolls back with it.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testACodeSentInsideTheCallersTransactionRollsBackWithIt(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        $factor  = $this->challengedFactor();
        $binding = $this->challengeBinding();
        $sent    = null;

        try {
            DB::connection(StorageConnection::name())->transaction(function () use ($factor, $binding, &$sent): never {

                $sent = $this->challengeGateway()->send($this->challengeCaller(), $factor, $binding);

                throw new \RuntimeException(self::ROLLED_BACK);
            });
        } catch (\RuntimeException $exception) {
            self::assertSame(self::ROLLED_BACK, $exception->getMessage());
        }

        self::assertInstanceOf(SendResult::class, $sent);
        self::assertTrue($sent->wasSent());
        self::assertSame(0, OneTimeCode::query()->count());
        self::assertSame(0, $this->queuedDeliveries());
    }

    /**
     * A check inside the caller's transaction rolls back with it.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testACheckInsideTheCallersTransactionRollsBackWithIt(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        $challenge = $this->sentChallenge();
        $code      = $this->deliveredCode($challenge);
        $factor    = $this->challengedFactor();
        $binding   = $this->challengeBinding();

        try {
            DB::connection(StorageConnection::name())->transaction(function () use ($factor, $binding, $challenge, $code): never {

                $checked = $this->challengeGateway()->verify($this->challengeCaller(), $factor, $binding, $challenge, self::wrong($code));

                self::assertSame(FailureReason::INVALID_CODE, $checked->reason);
                self::assertSame(1, $this->failures());

                throw new \RuntimeException(self::ROLLED_BACK);
            });
        } catch (\RuntimeException $exception) {
            self::assertSame(self::ROLLED_BACK, $exception->getMessage());
        }

        self::assertSame(0, $this->failures());
        self::assertTrue($this->challengeGateway()->verify($this->challengeCaller(), $factor, $binding, $challenge, $code)->hasPassed());
    }

    /**
     * The person signed in on the guard, served to the tests' client.
     *
     * @return \SineMacula\Laravel\Mfa\Context\CallerContext
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function challengeCaller(): CallerContext
    {
        return self::callerOf($this->person());
    }

    /**
     * The gateway under test, as the container builds it.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\ChallengeGateway
     */
    #[\Override]
    protected function challengeGateway(): ChallengeGateway
    {
        return $this->app?->make(ChallengeGatewayAdapter::class) ?? self::fail('The application has not booted.');
    }

    /**
     * A confirmed SMS factor of a signed-in person's.
     *
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    #[\Override]
    protected function challengedFactor(): FactorModel
    {
        return $this->factor ??= $this->deliveredFactor($this->person());
    }

    /**
     * A step-up of the person's current session.
     *
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     */
    #[\Override]
    protected function challengeBinding(): ProofBinding
    {
        return $this->bindingOf($this->person(), Purpose::STEP_UP);
    }

    /**
     * The code delivered for the challenge, read from the fake sender.
     *
     * @param  string  $challengeId
     * @return string
     */
    #[\Override]
    protected function deliveredCode(string $challengeId): string
    {
        return $this->deliveredCodeTo(self::DELIVERED_PHONE);
    }

    /**
     * Bind the application's one-time code sender before the application boots.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $this->defineFactorCodes($app);
    }

    /**
     * The person signed in on the guard, acting on their session.
     *
     * @return \Tests\Fixtures\Models\Person
     *
     * @throws \Throwable
     */
    private function person(): Person
    {
        if ($this->person === null) {
            $this->person  = $this->createPerson();
            $this->session = $this->signInAndActOnSession($this->person);
        }

        return $this->person;
    }

    /**
     * The person's current session.
     *
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession
     *
     * @throws \Throwable
     */
    private function personsSession(): EloquentSession&Model
    {
        $this->person();

        return $this->session ?? self::fail('The person has not signed in.');
    }

    /**
     * Send a code for the kit's factor and return its challenge.
     *
     * @return string
     *
     * @throws \Throwable
     */
    private function sentChallenge(): string
    {
        $sent = $this->challengeGateway()->send($this->challengeCaller(), $this->challengedFactor(), $this->challengeBinding());

        return $sent->challengeId ?? self::fail(sprintf('No code was sent: [%s].', $sent->reason?->value));
    }

    /**
     * The kit's factor's failures in a row, as stored.
     *
     * @return int
     */
    private function failures(): int
    {
        $factor = $this->factor ?? self::fail('No factor has been challenged.');

        return FactorModel::query()->whereKey($factor->id)->sole()->getConsecutiveFailures();
    }

    /**
     * A code of the same length that is not the one given.
     *
     * @param  string  $code
     * @return string
     */
    private static function wrong(#[\SensitiveParameter] string $code): string
    {
        $zeros = str_repeat('0', strlen($code));

        return $code === $zeros ? str_repeat('1', strlen($code)) : $zeros;
    }

    /**
     * What the call throws, failing the test when it throws nothing.
     *
     * @param  \Closure(): mixed  $call
     * @return \Throwable
     */
    private static function thrownBy(\Closure $call): \Throwable
    {
        try {
            $call();
        } catch (\Throwable $exception) {
            return $exception;
        }

        self::fail('The call threw nothing.');
    }

    /**
     * The binding of a challenge of the person's current session.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     */
    private function bindingOf(Person $person, Purpose $purpose): ProofBinding
    {
        $owner   = ProofOwner::of($person);
        $session = $this->session ?? self::fail('The person has not signed in.');

        return new ProofBinding($owner->type, $owner->key, self::GUARD, $this->signInReference($session), $purpose);
    }
}
