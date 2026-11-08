<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Testing;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Iam\Mfa\CurrentSession;
use SineMacula\Laravel\Iam\Mfa\StepUpAdapter;
use SineMacula\Laravel\Iam\Mfa\Translation\IdentityReference;
use SineMacula\Laravel\Iam\Mfa\Translation\SignIn;
use SineMacula\Laravel\Mfa\Assurance\Evaluation;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Context\SessionFirstFactor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\RequirementCheck;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Enums\RequirementPart;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;

/**
 * Arranges what `Concerns\InteractsWithIam::actingOnVerifiedSession()`
 * promises: the session the test acts on holds a further proof, recorded by
 * `laravel-authentication`, made with a factor the identity holds, so that its
 * proofs evaluate at exactly a given level.
 *
 * With this package's proof store bound, a session's proofs are the ones
 * `laravel-authentication` records, and a proof counts only while it names a
 * factor the identity holds in MFA's factor table. So MFA's own
 * `actingAsVerified()`, which records synthetic proofs through the store, is
 * refused here. This records the proof as a real step-up does instead: it takes
 * a confirmed factor of the level's type the identity holds, or enrols a
 * confirmed fixture factor of that type for it on the guard's application when
 * it holds none (`FixtureFactors`), and steps the session up with a proof made
 * with it through the step-up adapter, so `laravel-authentication` locks the
 * session's row, checks it is still one of the guard's live, active sessions of
 * a person, and records the proof, flagged multifactor exactly when MFA's own
 * acceptance would say it refreshes the multifactor evidence: when MFA's
 * requirement check, judging the session's first factor and this proof alone,
 * dates that evidence to this proof. The proofs are then read back through the
 * same `SessionFirstFactor::proofs()` and `RequirementCheck` MFA's route gate
 * uses, against additional verification and the level, exactly as MFA's own
 * helper reads them.
 *
 * The level's evidence is MFA's own helper's (`LevelEvidence`): an email code
 * to a synthetic address for AAL1, an authenticator app for AAL2, and a
 * hardware-protected, phishing-resistant passkey for AAL3, which MFA's default
 * combination policy rates AAL2, so it needs a policy that rates such evidence
 * AAL3.
 *
 * Stateless: the guard, the session and the identity are read on every call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class VerifiedSession
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Testing\FixtureFactors  $factors
     * @param  \SineMacula\Laravel\Iam\Mfa\CurrentSession  $current
     * @param  \SineMacula\Laravel\Iam\Mfa\StepUpAdapter  $stepUp
     * @param  \SineMacula\Laravel\Mfa\Context\SessionFirstFactor  $proofs
     * @param  \SineMacula\Laravel\Mfa\Contracts\RequirementCheck  $check
     */
    public function __construct(

        /** The factor of the level's type the identity holds, or one enrolled for it. */
        private FixtureFactors $factors,

        /** Resolves the default guard, the identity it serves and its current session. */
        private CurrentSession $current,

        /** Steps the session up through `laravel-authentication`. */
        private StepUpAdapter $stepUp,

        /** Reads the sign-in's proofs as MFA's route gate reads them. */
        private SessionFirstFactor $proofs,

        /** Evaluates the proofs as MFA's route gate evaluates them. */
        private RequirementCheck $check,
    ) {}

    /**
     * Verify the default guard's current session at exactly the level.
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
        $session     = $this->current->current($identity, $application);
        $evidence    = LevelEvidence::of($level);
        $binding     = self::binding($identity, $application, SignIn::reference($session, $application));
        $proof       = $evidence->proof($this->factors->held($identity, $application, $evidence->type), $binding, VerificationGeneration::current($identity));

        $this->stepUp->stepUp(CallerContext::forIdentity($identity, $application), VerificationResult::verified(
            $proof,
            $this->check->check(Requirement::none(), ...array_merge($this->proofs->proofs($identity, $application), [$proof])),
            $evidence->amr,
            $evidence->type,
            $this->refreshesMultifactor($identity, $application, $proof),
        ));

        self::assertReached($level, $this->check->check(
            Requirement::none()->withAdditionalVerification()->withMinimumLevel($level),
            ...$this->proofs->proofs($identity, $application),
        ));
    }

    /**
     * Refuse the unclassified level, which no proof supports, so a caller can
     * be refused it before anything is signed in or recorded.
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

    /**
     * Whether the proof refreshes the multifactor evidence of the sign-in's
     * first factor, as MFA's own acceptance judges it: the first factor and the
     * proof alone are multifactor, and the freshest evidence of that is the
     * proof's own. A sign-in whose first factor is not known is refused, as MFA
     * refuses every proof after it.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return bool
     *
     * @throws \LogicException
     */
    private function refreshesMultifactor(MultiFactorAuthenticatable $identity, string $application, Proof $proof): bool
    {
        $firstFactor = $this->proofs->current($identity, $application) ?? throw new \LogicException('The session\'s first factor is not known, so no proof is accepted after it.');

        return $this->check->check(Requirement::none(), $firstFactor, $proof)->multifactorAt?->equalTo($proof->provedAt) ?? false;
    }

    /**
     * What a step-up proof of the session is bound to.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity&\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $signIn
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private static function binding(Identity&MultiFactorAuthenticatable $identity, string $application, string $signIn): ProofBinding
    {
        $owner = IdentityReference::of($identity);

        return new ProofBinding($owner->type, $owner->key, $application, $signIn, Purpose::STEP_UP);
    }

    /**
     * Refuse a session whose proofs fell short of the level or went past it.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $level
     * @param  \SineMacula\Laravel\Mfa\Assurance\Evaluation  $evaluation
     * @return void
     *
     * @throws \LogicException
     */
    private static function assertReached(AssuranceLevel $level, Evaluation $evaluation): void
    {
        if ($evaluation->meetsRequirement() && $evaluation->level === $level) {
            return;
        }

        $unmet  = array_map(static fn (RequirementPart $part): string => $part->value, $evaluation->unmet);
        $listed = $unmet === [] ? 'none' : implode(', ', $unmet);

        throw new \LogicException(sprintf('Requested %s with additional verification; reached %s; unmet: %s.', $level->value, $evaluation->level->value, $listed));
    }
}
