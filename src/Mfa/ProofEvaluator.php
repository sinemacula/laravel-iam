<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Mfa\Contracts\RequirementCheck;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\RequirementPart;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * MFA's judgement of a proof it has just verified, on its own after the
 * session's first factor: the evaluation `laravel-authentication` records with
 * the proof when the step-up and pending completion adapters hand it over
 * (IAM-3.2, IAM-3.4, IAM-3.5).
 *
 * `laravel-authentication` keeps the evaluation on the proof's own row, and its
 * freshness reads "multifactor within so many seconds" as the newest proof
 * flagged multifactor, timed by that proof. So the flag must say whether this
 * proof is the evidence of a multifactor combination, never whether the session
 * holds one: MFA's `VerificationResult::$evaluation` judges every proof the
 * session holds with the new one, and would flag a fresh email code multifactor
 * because of an authenticator app code proved hours before, so a fresh weaker
 * proof would refresh an old stronger one, which MFA's own requirement check
 * never does.
 *
 * The proof is judged by MFA's requirement check with the session's first
 * factor alone, as MFA's own acceptance of a proof judges it, asking for
 * multifactor authentication within the longest age `laravel-authentication`'s
 * freshness holds a session to, as if the proof had been made now and the first
 * factor a second longer ago than that age. The part is then met only on the
 * proof's own evidence, so the proof is multifactor only when it completes a
 * multifactor combination: a first factor that is a multi-factor authenticator
 * on its own (a passkey that verified the person) followed by a proof that is
 * not keeps its evidence at sign-in, and the proof is not flagged. Only the
 * times are moved; the proofs are otherwise judged as they are, by whichever
 * combination policy MFA has bound.
 *
 * A session whose first factor is not known, and a proof MFA does not accept
 * after it, are refused with an `OperationRefusedException` carrying
 * `not_accepted`, as MFA's own acceptance refuses them, so nothing reaches the
 * session and the verification rolls back.
 *
 * Stateless: MFA's requirement check is the one bound, and nothing is kept
 * between calls (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ProofEvaluator
{
    /** @var string Why a proof is refused on a session whose first factor is not known. */
    private const string NO_FIRST_FACTOR = 'The session\'s first factor is not known, as the session is no longer live and active or its first factor no longer counts,'
        . ' so no proof is accepted after it.';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\RequirementCheck  $check
     */
    public function __construct(

        /** MFA's requirement check, the one asked. */
        private RequirementCheck $check,
    ) {}

    /**
     * `laravel-authentication`'s evaluation of the proof, made after the first
     * factor given: accepted, and multifactor when the proof is the evidence of
     * a multifactor combination with it.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Proofs\Proof  $firstFactor
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return \SineMacula\Laravel\Authentication\Proofs\Evaluation
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    public function evaluate(?Proof $firstFactor, Proof $proof): Evaluation
    {
        if ($firstFactor === null) {
            throw new OperationRefusedException(FailureReason::NOT_ACCEPTED, self::NO_FIRST_FACTOR);
        }

        $now        = CarbonImmutable::now();
        $window     = FreshnessRequirement::MAX_AGE_SECONDS;
        $evaluation = $this->check->check(
            Requirement::none()->withMultifactor($window),
            self::madeAt($firstFactor, $now->subSeconds($window)->subSecond()),
            self::madeAt($proof, $now),
        );

        OperationRefusedException::unless($evaluation->accepted, FailureReason::NOT_ACCEPTED, 'The proof is not accepted after the session\'s first factor.');

        return new Evaluation(true, in_array(RequirementPart::MULTIFACTOR, $evaluation->met, true));
    }

    /**
     * The proof as if it had been made at the time given.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @param  \Carbon\CarbonImmutable  $at
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     *
     * @throws \InvalidArgumentException
     */
    private static function madeAt(Proof $proof, CarbonImmutable $at): Proof
    {
        return new Proof($proof->kind, $proof->method, $proof->channel, $proof->reference, $proof->properties, $at, $proof->binding, $proof->generation, $proof->challengeId);
    }
}
