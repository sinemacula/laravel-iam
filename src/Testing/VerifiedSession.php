<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Testing;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Iam\Mfa\CurrentSession;
use SineMacula\Laravel\Iam\Mfa\StepUpAdapter;
use SineMacula\Laravel\Iam\Mfa\Translation\IdentityReference;
use SineMacula\Laravel\Iam\Mfa\Translation\SignIn;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Context\SessionFirstFactor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\RequirementCheck;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Testing\LevelEvidence;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;

/**
 * Steps a session up through `laravel-authentication` with MFA's level
 * evidence, for `InteractsWithIam::actingOnVerifiedSession()` and the recorder.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class VerifiedSession
{
    /** @var array<string, list<string>> The `amr` values of each method MFA's level evidence proves with. */
    public const array AMR = ['email' => ['otp'], 'totp' => ['otp'], 'passkey' => ['pop', 'user', 'hwk']];

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Iam\Testing\FixtureFactors  $factors
     * @param  \SineMacula\Laravel\Iam\Mfa\CurrentSession  $current
     * @param  \SineMacula\Laravel\Iam\Mfa\StepUpAdapter  $stepUp
     * @param  \SineMacula\Laravel\Mfa\Context\SessionFirstFactor  $proofs
     * @param  \SineMacula\Laravel\Mfa\Contracts\RequirementCheck  $check
     */
    public function __construct(

        /** Evaluates the session as MFA's route gate does. */
        private Container $container,

        /** The real factor the further proof names. */
        private FixtureFactors $factors,

        /** Resolves the default guard, its identity and its current session. */
        private CurrentSession $current,

        /** Steps the session up through `laravel-authentication`. */
        private StepUpAdapter $stepUp,

        /** Reads the session's proofs as MFA reads them. */
        private SessionFirstFactor $proofs,

        /** Evaluates the proofs as MFA does. */
        private RequirementCheck $check,
    ) {}

    /**
     * Verify the default guard's current session now at exactly the level.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $level
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \Throwable
     */
    public function verify(AssuranceLevel $level): void
    {
        self::assertClassified($level);

        $application = $this->current->defaultGuard();
        $identity    = $this->current->caller($application);
        $signIn      = SignIn::reference($this->current->current($identity, $application), $application);
        $owner       = IdentityReference::of($identity);
        $binding     = new ProofBinding($owner->type, $owner->key, $application, $signIn, Purpose::STEP_UP);
        $factor      = $this->factors->held($identity, $application, $level);

        $this->stepUp($identity, LevelEvidence::furtherProof($level, CarbonImmutable::now(), $binding, VerificationGeneration::current($identity), $factor));

        LevelEvidence::assertReached($level, LevelEvidence::evaluate($this->container, $identity, $application, $signIn, $level));
    }

    /**
     * Step the identity's current session up with the proof, judged with its
     * first factor as MFA judges a step-up.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return void
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \Throwable
     */
    public function stepUp(MultiFactorAuthenticatable $identity, Proof $proof): void
    {
        $application = $proof->binding->application;
        $judged      = $this->check->check(Requirement::none(), ...array_filter([$this->proofs->current($identity, $application), $proof]));

        $this->stepUp->stepUp(CallerContext::forIdentity($identity, $application), VerificationResult::verified(
            $proof,
            $judged,
            self::AMR[$proof->method] ?? [],
            $proof->method,
            $judged->multifactorAt?->equalTo($proof->provedAt) ?? false,
        ));
    }

    /**
     * Refuse the unclassified level, which no proof supports.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $level
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public static function assertClassified(AssuranceLevel $level): void
    {
        if ($level === AssuranceLevel::UNCLASSIFIED) {
            throw new \InvalidArgumentException('A session cannot be verified at the unclassified level: it supports no level.');
        }
    }
}
