<?php

declare(strict_types = 1);

namespace Tests\Unit\Mfa\Translation;

use Carbon\CarbonImmutable;
use Illuminate\Auth\GenericUser;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Codes\CodeRequest;
use SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeOutcome;
use SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeRefusal;
use SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeStanding;
use SineMacula\Laravel\Authentication\Codes\FactorCodeBinding;
use SineMacula\Laravel\Authentication\Codes\FactorCodeCheck;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Proofs\Channel as AuthenticationChannel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind as AuthenticationChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose as AuthenticationPurpose;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding as AuthenticationBinding;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\Translation\ChannelTranslator;
use SineMacula\Laravel\Iam\Mfa\Translation\CodeTranslator;
use SineMacula\Laravel\Iam\Mfa\Translation\ProofTranslator;
use SineMacula\Laravel\Mfa\Attempts\AttemptOutcome;
use SineMacula\Laravel\Mfa\Attempts\ChallengeAdmission;
use SineMacula\Laravel\Mfa\Attempts\Lockout;
use SineMacula\Laravel\Mfa\Enums\AttemptScope;
use SineMacula\Laravel\Mfa\Enums\ChannelKind as MfaChannelKind;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose as MfaPurpose;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding as MfaBinding;
use Tests\Fixtures\Mfa\Codes\DetachedFactor;

/**
 * Unit tests for translating a delivered factor's code challenges between MFA
 * and `laravel-authentication`: the binding both ways, MFA's admission and
 * counted attempt into `laravel-authentication`'s admission, and
 * `laravel-authentication`'s code request and check into MFA's send result and
 * challenge outcome.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CodeTranslator::class)]
final class CodeTranslatorTest extends TestCase
{
    /** @var string The number the factors' codes go to. */
    private const string PHONE = '+447700900123';

    /** @var string The application the challenges are on. */
    private const string APPLICATION = 'api';

    /** @var string The sign-in the challenges are bound to. */
    private const string SESSION = 'session-1';

    /** @var \Carbon\CarbonImmutable The time the tests run at. */
    private CarbonImmutable $now;

    /**
     * Freeze the clock.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->now = CarbonImmutable::createStrict(2026, 11, 5, 12, 0, 0);

        CarbonImmutable::setTestNow($this->now);
    }

    /**
     * Release the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * Rows of `[MFA purpose, authentication purpose, whether the binding holds a grant]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Mfa\Enums\Purpose, 1: \SineMacula\Laravel\Authentication\Proofs\Enums\Purpose, 2: bool}>
     */
    public static function providePurposes(): iterable
    {
        yield 'sign-in' => [MfaPurpose::SIGN_IN, AuthenticationPurpose::SIGN_IN, false];

        yield 'step-up' => [MfaPurpose::STEP_UP, AuthenticationPurpose::STEP_UP, false];

        yield 'enrolment' => [MfaPurpose::ENROLLMENT, AuthenticationPurpose::ENROLLMENT, true];
    }

    /**
     * MFA's binding becomes the factor code binding of the identity, the
     * application, the sign-in and the purpose, for the factor by its id on its
     * channel; an enrolment's is bound to the pending factor as its grant, and
     * MFA's binding comes back unchanged from it.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $mfa
     * @param  \SineMacula\Laravel\Authentication\Proofs\Enums\Purpose  $authentication
     * @param  bool  $granted
     * @return void
     */
    #[DataProvider('providePurposes')]
    public function testABindingCrossesBothWays(MfaPurpose $mfa, AuthenticationPurpose $authentication, bool $granted): void
    {
        $identity = self::identity();
        $binding  = new MfaBinding($identity::class, '7', self::APPLICATION, self::SESSION, $mfa);
        $code     = self::translator()->toAuthentication($identity, new DetachedFactor('factor-1'), MfaChannelKind::SMS, $binding);

        self::assertSame($identity, $code->binding->identity);
        self::assertSame(self::APPLICATION, $code->binding->application);
        self::assertSame(self::SESSION, $code->binding->sessionId);
        self::assertSame($authentication, $code->binding->purpose);
        self::assertSame('factor-1', $code->factor);
        self::assertSame(AuthenticationChannelKind::SMS, $code->channel->kind);
        self::assertSame(self::PHONE, $code->channel->reference);
        self::assertSame($granted ? 'factor-1' : null, $code->grant);
        self::assertSame($binding->toArray(), self::translator()->toMfa($identity, $code)->toArray());
    }

    /**
     * A factor numbered by an integer is named by its number, and a factor
     * whose id is neither a string nor an integer by nothing, which a factor
     * code binding refuses.
     *
     * @return void
     */
    public function testAFactorIsNamedByItsIdAsText(): void
    {
        self::assertSame('42', CodeTranslator::reference(new DetachedFactor(42)));
        self::assertSame('factor-1', CodeTranslator::reference(new DetachedFactor('factor-1')));
        self::assertSame('', CodeTranslator::reference(new DetachedFactor(null)));
        self::assertSame('', CodeTranslator::reference(new DetachedFactor(1.5)));
    }

    /**
     * A factor's channel is the kind its driver states, naming its destination.
     *
     * @return void
     */
    public function testAFactorsChannelNamesItsDestination(): void
    {
        $channel = self::translator()->channel(new DetachedFactor('factor-1', 'email', 'ada@example.test'), MfaChannelKind::EMAIL);

        self::assertSame(AuthenticationChannelKind::EMAIL, $channel->kind);
        self::assertSame('ada@example.test', $channel->reference);
    }

    /**
     * A session named by an integer key is MFA's sign-in by its number.
     *
     * @return void
     */
    public function testASessionNumberedByAnIntegerIsNamedByItsNumber(): void
    {
        $binding = self::factorCodeBinding(12);

        self::assertSame('12', self::translator()->toMfa(self::identity(), $binding)->sessionId);
    }

    /**
     * A session key that is neither a string nor an integer names no sign-in
     * MFA could refer back to, and cannot be resolved.
     *
     * @return void
     */
    public function testASessionKeyOfAnotherKindCannotBeResolved(): void
    {
        $refusal = null;

        try {
            self::translator()->toMfa(self::identity(), self::factorCodeBinding(1.5));
        } catch (UnresolvedReferenceException $exception) {
            $refusal = $exception;
        }

        self::assertInstanceOf(UnresolvedReferenceException::class, $refusal);
        self::assertSame(ReferenceKind::SESSION, $refusal->kind);
        self::assertSame(self::APPLICATION, $refusal->application);
    }

    /**
     * Rows of `[MFA's reason, the refusal it crosses as]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Mfa\Enums\FailureReason, 1: \SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeRefusal}>
     */
    public static function provideRefusals(): iterable
    {
        yield 'not found' => [FailureReason::NOT_FOUND, FactorCodeRefusal::NOT_FOUND];

        yield 'type not enabled' => [FailureReason::TYPE_NOT_ENABLED, FactorCodeRefusal::TYPE_NOT_ENABLED];

        yield 'no factor' => [FailureReason::NO_FACTOR, FactorCodeRefusal::NO_FACTOR];

        yield 'identity inactive' => [FailureReason::IDENTITY_INACTIVE, FactorCodeRefusal::IDENTITY_INACTIVE];

        yield 'machine identity' => [FailureReason::MACHINE_IDENTITY, FactorCodeRefusal::MACHINE_IDENTITY];

        yield 'sending capped' => [FailureReason::SENDING_CAPPED, FactorCodeRefusal::SENDING_CAPPED];

        yield 'not accepted' => [FailureReason::NOT_ACCEPTED, FactorCodeRefusal::NOT_ACCEPTED];

        yield 'pending' => [FailureReason::NOT_CONFIRMED, FactorCodeRefusal::NOT_FOUND];

        yield 'enrolment expired' => [FailureReason::EXPIRED, FactorCodeRefusal::NOT_FOUND];
    }

    /**
     * MFA's refusal crosses by value, or as `not_found` for a reason
     * `laravel-authentication` has no word for.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeRefusal  $refusal
     * @return void
     */
    #[DataProvider('provideRefusals')]
    public function testARefusalCrossesByValue(FailureReason $reason, FactorCodeRefusal $refusal): void
    {
        $admission = self::translator()->admission(ChallengeAdmission::refuse($reason, 'Refused.'));

        self::assertSame(FactorCodeStanding::REFUSED, $admission->standing);
        self::assertSame($refusal, $admission->refusal);
    }

    /**
     * An admission crosses as admitted, and a lockout as a lock until it ends,
     * or with no end for a factor disabled at its failure ceiling.
     *
     * @return void
     */
    public function testAnAdmissionAndALockoutCross(): void
    {
        $until = $this->now->addMinutes(5);

        self::assertTrue(self::translator()->admission(ChallengeAdmission::admit())->isAdmitted());

        $locked   = self::translator()->admission(ChallengeAdmission::locked(Lockout::endingAt(AttemptScope::FACTOR, $until)));
        $disabled = self::translator()->admission(ChallengeAdmission::locked(Lockout::disabled()));

        self::assertSame(FactorCodeStanding::LOCKED, $locked->standing);
        self::assertTrue($until->equalTo($locked->lockedUntil));
        self::assertSame(FactorCodeStanding::LOCKED, $disabled->standing);
        self::assertNull($disabled->lockedUntil);
    }

    /**
     * Rows of `[MFA's outcome, whether the code matched, the standing it
     * crosses as, the refusal]`.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Mfa\Attempts\AttemptOutcome, 1: bool, 2: \SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeStanding, 3: ?\SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeRefusal}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideAttempts(): iterable
    {
        yield 'a match MFA passed' => [AttemptOutcome::pass(), true, FactorCodeStanding::ADMITTED, null];

        yield 'a wrong code MFA counted' => [AttemptOutcome::fail(), false, FactorCodeStanding::ADMITTED, null];

        yield 'a wrong code MFA did not count' => [AttemptOutcome::uncounted(), false, FactorCodeStanding::ADMITTED, null];

        yield 'a match MFA did not pass' => [AttemptOutcome::fail(), true, FactorCodeStanding::REFUSED, FactorCodeRefusal::NOT_ACCEPTED];

        yield 'a factor no longer stored' => [AttemptOutcome::notFound(), true, FactorCodeStanding::REFUSED, FactorCodeRefusal::NOT_FOUND];

        yield 'a lockout' => [AttemptOutcome::refuse(Lockout::disabled(AttemptScope::IDENTITY)), true, FactorCodeStanding::LOCKED, null];

        yield 'a wrong code whose count disabled the factor' => [AttemptOutcome::fail(Lockout::disabled()), false, FactorCodeStanding::LOCKED, null];

        yield 'a wrong code whose count held the identity' => [AttemptOutcome::fail(Lockout::disabled(AttemptScope::IDENTITY)), false, FactorCodeStanding::LOCKED, null];
    }

    /**
     * An attempt MFA counted crosses as whether its outcome stands.
     *
     * @param  \SineMacula\Laravel\Mfa\Attempts\AttemptOutcome  $outcome
     * @param  bool  $matched
     * @param  \SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeStanding  $standing
     * @param  ?\SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeRefusal  $refusal
     * @return void
     */
    #[DataProvider('provideAttempts')]
    public function testAnAttemptCrossesAsWhetherItsOutcomeStands(AttemptOutcome $outcome, bool $matched, FactorCodeStanding $standing, ?FactorCodeRefusal $refusal): void
    {
        $admission = self::translator()->attempt($outcome, $matched);

        self::assertSame($standing, $admission->standing);
        self::assertSame($refusal, $admission->refusal);
    }

    /**
     * A failure that locked the factor until a time crosses as that lock.
     *
     * @return void
     */
    public function testALockoutOfAnAttemptCrossesWithItsEnd(): void
    {
        $until     = $this->now->addMinutes(15);
        $admission = self::translator()->attempt(AttemptOutcome::refuse(Lockout::endingAt(AttemptScope::FACTOR, $until)), false);

        self::assertSame(FactorCodeStanding::LOCKED, $admission->standing);
        self::assertTrue($until->equalTo($admission->lockedUntil));
    }

    /**
     * A wrong code whose count locked the factor or the identity until a time
     * crosses as that lock, until it ends; one held at the failure ceiling
     * crosses as a lock with no end.
     *
     * @return void
     */
    public function testALockoutAWrongCodeCausedCrossesWithItsEnd(): void
    {
        $until    = $this->now->addMinutes(15);
        $factor   = self::translator()->attempt(AttemptOutcome::fail(Lockout::endingAt(AttemptScope::FACTOR, $until)), false);
        $identity = self::translator()->attempt(AttemptOutcome::fail(Lockout::endingAt(AttemptScope::IDENTITY, $until->addMinute())), false);
        $disabled = self::translator()->attempt(AttemptOutcome::fail(Lockout::disabled()), false);

        self::assertSame(FactorCodeStanding::LOCKED, $factor->standing);
        self::assertTrue($until->equalTo($factor->lockedUntil));
        self::assertSame(FactorCodeStanding::LOCKED, $identity->standing);
        self::assertTrue($until->addMinute()->equalTo($identity->lockedUntil));
        self::assertNull($disabled->lockedUntil);
    }

    /**
     * A code sent crosses as sent, with its challenge and when it expires.
     *
     * @return void
     */
    public function testASentCodeCrossesWithItsChallenge(): void
    {
        $expires = $this->now->addMinutes(10);
        $result  = self::translator()->sendResult(CodeRequest::sent($expires, $this->now, 'challenge-1'));

        self::assertTrue($result->wasSent());
        self::assertSame('challenge-1', $result->challengeId);
        self::assertTrue($expires->equalTo($result->expiresAt));
    }

    /**
     * A code answered as sent with no challenge is no factor code, and is
     * refused as a broken answer.
     *
     * @return void
     */
    public function testACodeSentWithNoChallengeIsRefused(): void
    {
        $this->expectException(\LogicException::class);

        self::translator()->sendResult(CodeRequest::sent($this->now->addMinutes(10), $this->now));
    }

    /**
     * Rows of `[authentication's request, MFA's reason, seconds to wait]`.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(\Carbon\CarbonImmutable): \SineMacula\Laravel\Authentication\Codes\CodeRequest, 1: \SineMacula\Laravel\Mfa\Enums\FailureReason, 2: ?int}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideRefusedRequests(): iterable
    {
        yield 'the cooldown or a limit' => [static fn (): CodeRequest => CodeRequest::rateLimited(30), FailureReason::SENDING_CAPPED, 30];

        yield 'a full delivery window' => [static fn (): CodeRequest => CodeRequest::deliveriesExhausted(40), FailureReason::SENDING_CAPPED, 40];

        yield 'a lock until a time' => [static fn (CarbonImmutable $now): CodeRequest => CodeRequest::locked($now->addMinutes(2)), FailureReason::LOCKED, 120];

        yield 'a lock with no end' => [static fn (): CodeRequest => CodeRequest::locked(null), FailureReason::LOCKED, null];

        yield 'a refusal of MFA\'s' => [static fn (): CodeRequest => CodeRequest::refused(FactorCodeRefusal::TYPE_NOT_ENABLED), FailureReason::TYPE_NOT_ENABLED, null];

        yield 'a refusal with no reason' => [static fn (): CodeRequest => CodeRequest::refused(null), FailureReason::NOT_FOUND, null];

        yield 'a method not allowed' => [static fn (): CodeRequest => CodeRequest::methodNotAllowed(), FailureReason::NOT_FOUND, null];

        yield 'an identifier refused' => [static fn (): CodeRequest => CodeRequest::identifierInvalid(), FailureReason::NOT_FOUND, null];
    }

    /**
     * A code request refused crosses as MFA's refusal, with how long to wait
     * when waiting will help.
     *
     * @param  \Closure(\Carbon\CarbonImmutable): \SineMacula\Laravel\Authentication\Codes\CodeRequest  $request
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  ?int  $retryAfter
     * @return void
     */
    #[DataProvider('provideRefusedRequests')]
    public function testARefusedRequestCrossesAsMfasRefusal(\Closure $request, FailureReason $reason, ?int $retryAfter): void
    {
        $result = self::translator()->sendResult($request($this->now));

        self::assertSame($reason, $result->reason);
        self::assertSame($retryAfter, $result->retryAfter);
        self::assertNull($result->challengeId);
    }

    /**
     * Rows of `[authentication's outcome, MFA's reason, the detail, whether it was counted]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeOutcome, 1: ?\SineMacula\Laravel\Mfa\Enums\FailureReason, 2: ?string, 3: bool}>
     */
    public static function provideChecks(): iterable
    {
        yield 'verified' => [FactorCodeOutcome::VERIFIED, null, null, true];

        yield 'invalid' => [FactorCodeOutcome::INVALID, FailureReason::INVALID_CODE, CodeTranslator::INVALID, true];

        yield 'not found' => [FactorCodeOutcome::NOT_FOUND, FailureReason::NOT_FOUND, CodeTranslator::NOT_FOUND, false];

        yield 'used' => [FactorCodeOutcome::USED, FailureReason::REPLAYED, CodeTranslator::REPLAYED, false];

        yield 'expired' => [FactorCodeOutcome::EXPIRED, FailureReason::EXPIRED, CodeTranslator::EXPIRED, false];

        yield 'exhausted' => [FactorCodeOutcome::EXHAUSTED, FailureReason::EXPIRED, CodeTranslator::EXPIRED, false];

        yield 'locked' => [FactorCodeOutcome::LOCKED, FailureReason::LOCKED, CodeTranslator::LOCKED, false];

        yield 'refused' => [FactorCodeOutcome::REFUSED, FailureReason::NOT_FOUND, CodeTranslator::REFUSED, false];

        yield 'rate limited' => [FactorCodeOutcome::RATE_LIMITED, FailureReason::LOCKED, CodeTranslator::RATE_LIMITED, false];
    }

    /**
     * Every check crosses as MFA's outcome: passed, a counted invalid code, or
     * refused for the reason, counting nothing.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeOutcome  $outcome
     * @param  ?\SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  ?string  $detail
     * @param  bool  $counted
     * @return void
     */
    #[DataProvider('provideChecks')]
    public function testEveryCheckCrossesAsMfasOutcome(FactorCodeOutcome $outcome, ?FailureReason $reason, ?string $detail, bool $counted): void
    {
        $translated = self::translator()->outcome(new FactorCodeCheck($outcome, 'challenge-1'));

        self::assertSame($reason, $translated->reason);
        self::assertSame($counted, $translated->counted);
        self::assertNull($translated->lockedUntil);

        if ($detail === null) {
            return;
        }

        self::assertSame($detail, $translated->detail);
    }

    /**
     * A lock carries its end, a refusal its reason, and the IP address's limit
     * the end of its window.
     *
     * @return void
     */
    public function testALockARefusalAndTheIpAddresssLimitCarryWhatTheySay(): void
    {
        $until   = $this->now->addMinutes(5);
        $locked  = self::translator()->outcome(new FactorCodeCheck(FactorCodeOutcome::LOCKED, 'challenge-1', lockedUntil: $until));
        $refused = self::translator()->outcome(new FactorCodeCheck(FactorCodeOutcome::REFUSED, 'challenge-1', refusal: FactorCodeRefusal::MACHINE_IDENTITY));
        $limited = self::translator()->outcome(new FactorCodeCheck(FactorCodeOutcome::RATE_LIMITED, 'challenge-1', retryAfter: 90));

        self::assertTrue($until->equalTo($locked->lockedUntil));
        self::assertSame(FailureReason::MACHINE_IDENTITY, $refused->reason);
        self::assertTrue($this->now->addSeconds(90)->equalTo($limited->lockedUntil));
    }

    /**
     * An identity `laravel-authentication` signs in.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     */
    private static function identity(): Identity
    {
        return new class (['id' => 7]) extends GenericUser implements Identity {};
    }

    /**
     * A step-up's factor code binding on the session given.
     *
     * @param  mixed  $session
     * @return \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding
     */
    private static function factorCodeBinding(mixed $session): FactorCodeBinding
    {
        $proof = new AuthenticationBinding(self::identity(), self::APPLICATION, $session, AuthenticationPurpose::STEP_UP);

        return new FactorCodeBinding($proof, 'factor-1', new AuthenticationChannel(AuthenticationChannelKind::SMS, self::PHONE));
    }

    /**
     * The translator under test.
     *
     * @return \SineMacula\Laravel\Iam\Mfa\Translation\CodeTranslator
     */
    private static function translator(): CodeTranslator
    {
        $channels = new ChannelTranslator;

        return new CodeTranslator(new ProofTranslator($channels), $channels);
    }
}
