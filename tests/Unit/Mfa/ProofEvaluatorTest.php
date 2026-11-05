<?php

declare(strict_types = 1);

namespace Tests\Unit\Mfa;

use Carbon\CarbonImmutable;
use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Mfa\ProofEvaluator;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\DefaultCombinationPolicy;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Contracts\CombinationPolicy;
use SineMacula\Laravel\Mfa\Contracts\RequirementCheck;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Enums\RequirementPart;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Requirements\ProofRequirementCheck;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * Unit tests for MFA's judgement of a proof it has just verified, on its own
 * after the session's first factor (IAM-3.2, IAM-3.4, IAM-3.5): the proof is
 * multifactor only when it is the evidence of a multifactor combination with
 * the first factor, never because of an older proof the session holds, and a
 * session without a first factor, or a proof MFA does not accept after it, is
 * refused.
 *
 * MFA's own requirement check and default combination policy judge, at a time
 * held still.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProofEvaluator::class)]
final class ProofEvaluatorTest extends TestCase
{
    /** @var string The application the sign-in is on. */
    private const string APPLICATION = 'api';

    /** @var string The sign-in's reference. */
    private const string SESSION = '42';

    /**
     * Hold the time still.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(CarbonImmutable::parse('2026-11-05 12:00:00'));
    }

    /**
     * Let the time run again.
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
     * A fresh email code after a password is accepted but is not multifactor,
     * although MFA's evaluation of the whole session, which also holds an
     * authenticator app code made hours before, is: the old code is not the
     * fresh proof's evidence.
     *
     * @return void
     */
    public function testAFreshEmailCodeAfterAnOldAuthenticatorAppCodeIsNotMultifactor(): void
    {
        $now         = CarbonImmutable::now();
        $firstFactor = self::firstFactor(new Channel(ChannelKind::PASSWORD), $now->subHours(3));
        $totp        = self::further(new Channel(ChannelKind::AUTHENTICATOR_APP, 'factor-totp'), 'factor-totp', $now->subHours(3)->addMinute());
        $email       = self::further(new Channel(ChannelKind::EMAIL, 'ada@example.test'), 'factor-email', $now);

        $session = self::check()->check(Requirement::none()->withMultifactor(300), $firstFactor, $totp, $email);

        self::assertTrue($session->multifactor);
        self::assertSame([RequirementPart::MULTIFACTOR], $session->unmet);

        $evaluation = self::evaluator()->evaluate($firstFactor, $email);

        self::assertTrue($evaluation->accepted);
        self::assertFalse($evaluation->multifactor);
    }

    /**
     * Rows of `[first factor's channel, whether it verified the person, further
     * proof's channel, whether it verified the person, whether the further
     * proof is multifactor]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Mfa\Assurance\Channel, 1: bool, 2: \SineMacula\Laravel\Mfa\Assurance\Channel, 3: bool, 4: bool}>
     */
    public static function provideCombinations(): iterable
    {
        $password      = new Channel(ChannelKind::PASSWORD);
        $email         = new Channel(ChannelKind::EMAIL, 'ada@example.test');
        $signInKey     = new Channel(ChannelKind::PASSKEY, 'credential-sign-in');
        $stepUpKey     = new Channel(ChannelKind::PASSKEY, 'credential-step-up');
        $authenticator = new Channel(ChannelKind::AUTHENTICATOR_APP, 'factor-totp');

        yield 'an authenticator app code after a password completes multifactor' => [$password, false, $authenticator, false, true];

        yield 'an email code after a password does not' => [$password, false, $email, false, false];

        yield 'an email code after a verified passkey leaves the evidence at sign-in' => [$signInKey, true, $email, false, false];

        yield 'a verified passkey after a verified passkey is its own evidence' => [$signInKey, true, $stepUpKey, true, true];
    }

    /**
     * The further proof is multifactor exactly when it is the evidence of a
     * multifactor combination with the first factor: never when the first
     * factor is a multi-factor authenticator on its own and the further proof
     * is not, however recently each was made.
     *
     * @param  \SineMacula\Laravel\Mfa\Assurance\Channel  $first
     * @param  bool  $firstVerified
     * @param  \SineMacula\Laravel\Mfa\Assurance\Channel  $further
     * @param  bool  $furtherVerified
     * @param  bool  $multifactor
     * @return void
     */
    #[DataProvider('provideCombinations')]
    public function testTheProofIsMultifactorOnlyOnItsOwnEvidence(Channel $first, bool $firstVerified, Channel $further, bool $furtherVerified, bool $multifactor): void
    {
        $now = CarbonImmutable::now();

        foreach ([$now->subHours(3), $now->subSecond(), $now] as $signedIn) {

            $evaluation = self::evaluator()->evaluate(
                self::firstFactor($first, $signedIn, self::observed($firstVerified)),
                self::further($further, 'factor-further', $now, self::observed($furtherVerified)),
            );

            self::assertTrue($evaluation->accepted);
            self::assertSame($multifactor, $evaluation->multifactor, sprintf('Signed in at [%s].', $signedIn->toIso8601String()));
        }
    }

    /**
     * A session whose first factor is not known accepts no proof, and the proof
     * is refused as not accepted.
     *
     * @return void
     */
    public function testAProofWithoutAFirstFactorIsRefused(): void
    {
        $proof = self::further(new Channel(ChannelKind::AUTHENTICATOR_APP, 'factor-totp'), 'factor-totp', CarbonImmutable::now());

        self::assertRefused(
            'The session\'s first factor is not known, as the session is no longer live and active or its first factor no longer counts, so no proof is accepted after it.',
            static fn (): mixed => self::evaluator()->evaluate(null, $proof),
        );
    }

    /**
     * A proof MFA does not accept after the first factor, one on the first
     * factor's own channel, is refused as not accepted.
     *
     * @return void
     */
    public function testAProofNotAcceptedAfterTheFirstFactorIsRefused(): void
    {
        $now     = CarbonImmutable::now();
        $channel = new Channel(ChannelKind::SMS, '+447700900123');

        self::assertRefused(
            'The proof is not accepted after the session\'s first factor.',
            static fn (): mixed => self::evaluator()->evaluate(self::firstFactor($channel, $now->subMinute()), self::further($channel, 'factor-sms', $now)),
        );
    }

    /**
     * Assert the call is refused as not accepted, with the detail given.
     *
     * @param  string  $detail
     * @param  \Closure(): mixed  $call
     * @return void
     */
    private static function assertRefused(string $detail, \Closure $call): void
    {
        try {
            $call();
        } catch (OperationRefusedException $exception) {
            self::assertSame(FailureReason::NOT_ACCEPTED, $exception->reason);
            self::assertSame($detail, $exception->getMessage());

            return;
        }

        self::fail('The proof was not refused.');
    }

    /**
     * What a proof observed: the person present and verified, or nothing.
     *
     * @param  bool  $verified
     * @return \SineMacula\Laravel\Mfa\Assurance\ObservedProperties
     */
    private static function observed(bool $verified): ObservedProperties
    {
        return $verified ? new ObservedProperties(userPresence: true, userVerification: true) : ObservedProperties::none();
    }

    /**
     * The evaluator, over MFA's own requirement check.
     *
     * @return \SineMacula\Laravel\Iam\Mfa\ProofEvaluator
     */
    private static function evaluator(): ProofEvaluator
    {
        return new ProofEvaluator(self::check());
    }

    /**
     * MFA's own requirement check, judging with its default combination policy.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\RequirementCheck
     */
    private static function check(): RequirementCheck
    {
        $container = new Container;

        $container->bind(CombinationPolicy::class, DefaultCombinationPolicy::class);

        return new ProofRequirementCheck($container);
    }

    /**
     * The sign-in's first factor, made on the channel and at the time given.
     *
     * @param  \SineMacula\Laravel\Mfa\Assurance\Channel  $channel
     * @param  \Carbon\CarbonImmutable  $at
     * @param  ?\SineMacula\Laravel\Mfa\Assurance\ObservedProperties  $observed
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    private static function firstFactor(Channel $channel, CarbonImmutable $at, ?ObservedProperties $observed = null): Proof
    {
        return new Proof(ProofKind::FIRST_FACTOR, $channel->kind->value, $channel, null, $observed ?? ObservedProperties::none(), $at, self::binding(Purpose::SIGN_IN), 0);
    }

    /**
     * A further factor's proof for a step-up of the sign-in, made with the
     * factor, on the channel and at the time given.
     *
     * @param  \SineMacula\Laravel\Mfa\Assurance\Channel  $channel
     * @param  string  $factor
     * @param  \Carbon\CarbonImmutable  $at
     * @param  ?\SineMacula\Laravel\Mfa\Assurance\ObservedProperties  $observed
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    private static function further(Channel $channel, string $factor, CarbonImmutable $at, ?ObservedProperties $observed = null): Proof
    {
        return new Proof(ProofKind::ADDITIONAL_FACTOR, $channel->kind->value, $channel, $factor, $observed ?? ObservedProperties::none(), $at, self::binding(Purpose::STEP_UP), 0);
    }

    /**
     * The binding of the sign-in's proofs, for the purpose given.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     */
    private static function binding(Purpose $purpose): ProofBinding
    {
        return new ProofBinding('person', '7', self::APPLICATION, self::SESSION, $purpose);
    }
}
