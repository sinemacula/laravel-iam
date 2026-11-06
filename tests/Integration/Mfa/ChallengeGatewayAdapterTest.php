<?php

declare(strict_types = 1);

namespace Tests\Integration\Mfa;

use Carbon\CarbonImmutable;
use Illuminate\Auth\AuthManager as LaravelAuthManager;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Models\OneTimeCode;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind as AuthenticationChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose as AuthenticationPurpose;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\ChallengeGatewayAdapter;
use SineMacula\Laravel\Iam\Mfa\CurrentSession;
use SineMacula\Laravel\Iam\Mfa\Translation\CodeTranslator;
use SineMacula\Laravel\Iam\Mfa\Translation\IdentityReference;
use SineMacula\Laravel\Mfa\Codes\SendResult;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor as FactorModel;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\ChallengeGatewayTests;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Mfa\Codes\Concerns\ArrangesDeliveredFactors;
use Tests\Fixtures\Mfa\Codes\Concerns\DeliversFactorCodes;
use Tests\Fixtures\Mfa\Codes\DetachedFactor;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * Integration tests for MFA's challenge gateway over `laravel-authentication`'s
 * factor codes (IAM-3.9): a code is issued and checked by
 * `laravel-authentication`, under a binding made from MFA's, with MFA's
 * challenge counters asked and told through this package's factor code counters
 * inside the same transaction, and delivered by `laravel-authentication`'s
 * one-time code sender once that commits, never by MFA's senders.
 *
 * Every adapter of this package's is bound, as an application runs them, and
 * the sessions are real ones, signed in through `laravel-authentication` with a
 * password, so MFA's counters read the session's first factor from it.
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
    use ArrangesDeliveredFactors, ChallengeGatewayTests, DeliversFactorCodes, MigratesMembers, RunsAtIsolationLevels, SignsInPeople;

    /** @var string Why the kit's checks of a used and an unknown challenge cannot pass. */
    private const string INDISTINCT = 'laravel-authentication answers a used, unknown or malformed challenge `invalid`, as it does a wrong code (member gap).';

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
     * A code sent through the gateway is issued by `laravel-authentication` and
     * delivered by its one-time code sender, once, as a further factor's code
     * to the factor's destination for the person on the guard, never by MFA's
     * own senders.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACodeIsSentThroughAuthentication(): void
    {
        $sent = $this->challengeGateway()->send($this->challengedFactor(), $this->challengeBinding());

        self::assertTrue($sent->wasSent());
        self::assertNotNull($sent->challengeId);
        self::assertSame(1, $this->queuedDeliveries());

        $messages = $this->deliverFactorCodes();

        self::assertCount(1, $messages);
        self::assertSame(CodePurpose::MFA, $messages[0]->purpose);
        self::assertSame('sms', $messages[0]->type);
        self::assertSame(self::DELIVERED_PHONE, $messages[0]->identifier);
        self::assertSame(self::GUARD, $messages[0]->guard);
        self::assertTrue($messages[0]->expiresAt->equalTo($sent->expiresAt));
        self::assertSame($this->person()->getKey(), $messages[0]->identity->getAuthIdentifier());

        foreach ($this->gateways() as $gateway) {
            self::assertSame([], $gateway->sent());
        }
    }

    /**
     * The kit's check that a used code answers as `replayed` cannot pass:
     * `laravel-authentication` answers a used challenge `invalid`, as it does a
     * wrong code, and says nothing more (member gap, reported).
     * `testAUsedCodeNeverAnswersAgain` pins what the gateway answers instead.
     *
     * @return void
     */
    public function testChallengeGatewayConsumesACodeOnce(): void
    {
        self::markTestSkipped(self::INDISTINCT);
    }

    /**
     * The kit's check that an unknown challenge answers as `not_found` cannot
     * pass: `laravel-authentication` answers a malformed or unknown challenge
     * `invalid`, as it does a wrong code, and says nothing more (member gap,
     * reported). `testAnUnknownChallengeNeverPasses` pins what the gateway
     * answers instead.
     *
     * @return void
     */
    public function testChallengeGatewayDoesNotFindAnUnknownChallenge(): void
    {
        self::markTestSkipped(self::INDISTINCT);
    }

    /**
     * A step-up is proved end to end with a code MFA asks for and checks
     * through the gateway: `laravel-authentication` delivers it, and once it is
     * checked the session records the step-up with the SMS factor.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStepUpIsProvedWithACodeThroughAuthentication(): void
    {
        $factor = $this->challengedFactor();
        $sent   = Mfa::sendCode($factor->id, Purpose::STEP_UP);

        self::assertTrue($sent->wasSent(), (string) $sent->reason?->value);

        $code     = $this->deliveredCodeTo(self::DELIVERED_PHONE);
        $verified = Mfa::verify(Submission::challenge($factor->id, (string) $sent->challengeId, $code), Purpose::STEP_UP);

        self::assertTrue($verified->isVerified(), (string) $verified->reason?->value);

        $proof = $this->proofsOf($this->personsSession())[0];

        self::assertSame(AuthenticationPurpose::STEP_UP, $proof->purpose);
        self::assertSame($factor->id, $proof->factor);
        self::assertSame(AuthenticationChannelKind::SMS, $proof->channel->kind);
        self::assertSame(self::DELIVERED_PHONE, $proof->channel->reference);

        foreach ($this->gateways() as $gateway) {
            self::assertSame([], $gateway->sent());
        }
    }

    /**
     * An SMS factor is enrolled end to end, on a session that has just proved
     * its password again: MFA's first code goes out through
     * `laravel-authentication` as an enrolment's, bound to the pending factor,
     * and confirms it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnEnrolmentIsConfirmedWithACodeThroughAuthentication(): void
    {
        $person          = $this->person();
        $reauthenticated = $this->sessions()->reauthenticate($this->personsSession(), 'password', ['email' => $person->email, 'password' => self::PASSWORD]);

        self::assertTrue($reauthenticated->isIssued());

        $start = Mfa::startEnrollment(EnrollmentRequest::delivered('sms', self::OTHER_PHONE));

        self::assertTrue($start->hasStarted(), (string) $start->reason?->value);
        self::assertNotNull($start->grant);

        $messages = $this->deliverFactorCodes();

        self::assertCount(1, $messages);
        self::assertSame(CodePurpose::ENROLLMENT, $messages[0]->purpose);

        $confirmation = Mfa::confirmEnrollment($start->grant, $messages[0]->code->reveal());

        self::assertTrue($confirmation->isConfirmed(), (string) $confirmation->reason?->value);
        self::assertTrue(FactorModel::query()->where('destination', self::OTHER_PHONE)->sole()->isConfirmed());
    }

    /**
     * A wrong code fails as an invalid code, and is counted against the factor
     * by MFA's challenge counters.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAWrongCodeIsCountedAgainstTheFactor(): void
    {
        $challenge = $this->sentChallenge();
        $outcome   = $this->challengeGateway()->verify($this->challengedFactor(), $this->challengeBinding(), $challenge, self::wrong($this->deliveredCode($challenge)));

        self::assertSame(FailureReason::INVALID_CODE, $outcome->reason);
        self::assertSame(CodeTranslator::INVALID, $outcome->detail);
        self::assertTrue($outcome->counted);
        self::assertSame(1, $this->failures());
    }

    /**
     * A used code never answers its challenge again: it fails as an invalid
     * code, and is counted against nothing, as `laravel-authentication` reports
     * no attempt at a used challenge.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAUsedCodeNeverAnswersAgain(): void
    {
        $challenge = $this->sentChallenge();
        $code      = $this->deliveredCode($challenge);

        self::assertTrue($this->challengeGateway()->verify($this->challengedFactor(), $this->challengeBinding(), $challenge, $code)->hasPassed());

        $again = $this->challengeGateway()->verify($this->challengedFactor(), $this->challengeBinding(), $challenge, $code);

        self::assertSame(FailureReason::INVALID_CODE, $again->reason);
        self::assertSame(0, $this->failures());
    }

    /**
     * A challenge that is not the binding's never passes: it fails as an
     * invalid code, and is counted against nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnknownChallengeNeverPasses(): void
    {
        $outcome = $this->challengeGateway()->verify($this->challengedFactor(), $this->challengeBinding(), 'unknown-challenge', '000000');

        self::assertSame(FailureReason::INVALID_CODE, $outcome->reason);
        self::assertSame(0, $this->failures());
    }

    /**
     * A code checked once it has expired is refused as expired, and counted
     * against nothing.
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

        $outcome = $this->challengeGateway()->verify($this->challengedFactor(), $this->challengeBinding(), $challenge, $code);

        self::assertSame(FailureReason::EXPIRED, $outcome->reason);
        self::assertSame(CodeTranslator::EXPIRED, $outcome->detail);
        self::assertFalse($outcome->counted);
        self::assertSame(0, $this->failures());
    }

    /**
     * A factor MFA has locked is sent no code, refused as locked with how long
     * until the lock ends, and checked against nothing.
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

        $sent    = $this->challengeGateway()->send($factor, $this->challengeBinding());
        $outcome = $this->challengeGateway()->verify($factor, $this->challengeBinding(), $challenge, $code);

        self::assertSame(FailureReason::LOCKED, $sent->reason);
        self::assertSame(600, $sent->retryAfter);
        self::assertSame(0, $this->queuedDeliveries());
        self::assertSame(FailureReason::LOCKED, $outcome->reason);
        self::assertSame(CodeTranslator::LOCKED, $outcome->detail);
        self::assertFalse($outcome->counted);
        self::assertTrue($until->equalTo($outcome->lockedUntil));
    }

    /**
     * A factor of a type the application no longer offers is sent no code, and
     * refused for MFA's reason.
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

        $sent    = $this->challengeGateway()->send($this->challengedFactor(), $this->challengeBinding());
        $outcome = $this->challengeGateway()->verify($this->challengedFactor(), $this->challengeBinding(), $challenge, $code);

        self::assertSame(FailureReason::TYPE_NOT_ENABLED, $sent->reason);
        self::assertSame(FailureReason::TYPE_NOT_ENABLED, $outcome->reason);
        self::assertSame(CodeTranslator::REFUSED, $outcome->detail);
        self::assertFalse($outcome->counted);
    }

    /**
     * A code asked for again before `laravel-authentication`'s cooldown ends is
     * refused as sending capped, with how long to wait.
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

        $again = $this->challengeGateway()->send($this->challengedFactor(), $this->challengeBinding());

        self::assertSame(FailureReason::SENDING_CAPPED, $again->reason);
        self::assertSame(60, $again->retryAfter);
        self::assertSame(1, $this->queuedDeliveries());
    }

    /**
     * Checks beyond `laravel-authentication`'s limit for the IP address are
     * refused as locked until its window ends, and counted against nothing.
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

        $this->challengeGateway()->verify($this->challengedFactor(), $this->challengeBinding(), $challenge, $wrong);

        $outcome = $this->challengeGateway()->verify($this->challengedFactor(), $this->challengeBinding(), $challenge, $wrong);

        self::assertSame(FailureReason::LOCKED, $outcome->reason);
        self::assertSame(CodeTranslator::RATE_LIMITED, $outcome->detail);
        self::assertFalse($outcome->counted);
        self::assertNotNull($outcome->lockedUntil);
        self::assertTrue($outcome->lockedUntil->isFuture());
        self::assertSame(1, $this->failures());
    }

    /**
     * A factor of another identity than the binding's is not found: no code is
     * sent for it, and none is checked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFactorOfAnotherIdentityIsNotFound(): void
    {
        $this->person();

        $factor  = $this->deliveredFactor($this->createPerson(), 'sms', self::OTHER_PHONE);
        $sent    = $this->challengeGateway()->send($factor, $this->challengeBinding());
        $outcome = $this->challengeGateway()->verify($factor, $this->challengeBinding(), 'unknown-challenge', '000000');

        self::assertSame(FailureReason::NOT_FOUND, $sent->reason);
        self::assertSame(FailureReason::NOT_FOUND, $outcome->reason);
        self::assertSame(ChallengeGatewayAdapter::NOT_FOUND, $outcome->detail);
        self::assertFalse($outcome->counted);
        self::assertSame(0, $this->queuedDeliveries());
        self::assertSame(0, OneTimeCode::query()->count());
    }

    /**
     * A factor that keeps no state of its own on a row is not found, as MFA
     * finds none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFactorKeepingNoStateIsNotFound(): void
    {
        $factor = new DetachedFactor;

        self::assertSame(FailureReason::NOT_FOUND, $this->challengeGateway()->send($factor, $this->challengeBinding())->reason);
        self::assertSame(FailureReason::NOT_FOUND, $this->challengeGateway()->verify($factor, $this->challengeBinding(), 'unknown-challenge', '000000')->reason);
        self::assertSame(0, OneTimeCode::query()->count());
    }

    /**
     * A reauthentication proves the first factor, so no code is sent or checked
     * for one: both are refused as not accepted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReauthenticationIsNotAccepted(): void
    {
        $binding = $this->bindingOf($this->person(), Purpose::REAUTHENTICATE);
        $outcome = $this->challengeGateway()->verify($this->challengedFactor(), $binding, 'unknown-challenge', '000000');

        self::assertSame(FailureReason::NOT_ACCEPTED, $this->challengeGateway()->send($this->challengedFactor(), $binding)->reason);
        self::assertSame(FailureReason::NOT_ACCEPTED, $outcome->reason);
        self::assertSame(ChallengeGatewayAdapter::REAUTHENTICATION, $outcome->detail);
        self::assertSame(0, OneTimeCode::query()->count());
    }

    /**
     * An application that names no guard of `laravel-authentication`'s cannot
     * be resolved, and both a send and a check throw.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnApplicationThatIsNoGuardThrows(): void
    {
        $owner   = IdentityReference::of($this->person());
        $binding = new ProofBinding($owner->type, $owner->key, 'console', $this->signInReference($this->personsSession()), Purpose::STEP_UP);

        $calls = [
            fn (): mixed => $this->challengeGateway()->send($this->challengedFactor(), $binding),
            fn (): mixed => $this->challengeGateway()->verify($this->challengedFactor(), $binding, 'unknown-challenge', '000000'),
        ];

        foreach ($calls as $call) {
            $refusal = self::thrownBy($call);

            self::assertInstanceOf(UnresolvedReferenceException::class, $refusal);
            self::assertSame(ReferenceKind::GUARD, $refusal->kind);
            self::assertSame('console', $refusal->application);
        }
    }

    /**
     * An authentication factory that is not `laravel-authentication`'s holds no
     * factor codes, so the guard cannot be resolved.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAuthenticationFactoryOfAnotherKindThrows(): void
    {
        $app     = $this->app ?? self::fail('The application has not booted.');
        $gateway = new ChallengeGatewayAdapter(new LaravelAuthManager($app), $app->make(CurrentSession::class), $app->make(CodeTranslator::class), $app);
        $refusal = self::thrownBy(fn (): mixed => $gateway->send($this->challengedFactor(), $this->challengeBinding()));

        self::assertInstanceOf(UnresolvedReferenceException::class, $refusal);
        self::assertSame(ReferenceKind::GUARD, $refusal->kind);
    }

    /**
     * A code sent inside the caller's transaction is issued in it: when the
     * caller rolls back, no code is kept and none is delivered, at either
     * isolation level.
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

                $sent = $this->challengeGateway()->send($factor, $binding);

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
     * A code checked inside the caller's transaction is used up and counted in
     * it: when the caller rolls back, the failure MFA counted rolls back with
     * the attempt, and the right code still answers the challenge afterwards,
     * at either isolation level.
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

                self::assertSame(FailureReason::INVALID_CODE, $this->challengeGateway()->verify($factor, $binding, $challenge, self::wrong($code))->reason);
                self::assertSame(1, $this->failures());

                throw new \RuntimeException(self::ROLLED_BACK);
            });
        } catch (\RuntimeException $exception) {
            self::assertSame(self::ROLLED_BACK, $exception->getMessage());
        }

        self::assertSame(0, $this->failures());
        self::assertTrue($this->challengeGateway()->verify($factor, $binding, $challenge, $code)->hasPassed());
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
     * The code delivered for the challenge, read from
     * `laravel-authentication`'s fake sender once the delivery has run.
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
     * Bind the application's gateways before the application boots.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

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
     * Send a code for the kit's factor through the gateway, failing unless it
     * is sent, and return its challenge.
     *
     * @return string
     *
     * @throws \Throwable
     */
    private function sentChallenge(): string
    {
        $sent = $this->challengeGateway()->send($this->challengedFactor(), $this->challengeBinding());

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
     * The binding of a challenge of the person's current session for the
     * purpose.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     */
    private function bindingOf(Person $person, Purpose $purpose): ProofBinding
    {
        $owner   = IdentityReference::of($person);
        $session = $this->session ?? self::fail('The person has not signed in.');

        return new ProofBinding($owner->type, $owner->key, self::GUARD, $this->signInReference($session), $purpose);
    }
}
