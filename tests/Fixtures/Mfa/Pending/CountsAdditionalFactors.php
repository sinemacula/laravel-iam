<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Mfa\Pending;

use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Requirements\Enums\RequirementKind;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementEvaluation;
use SineMacula\Laravel\Authentication\Requirements\RequirementSubject;

/**
 * A requirement check that meets an additional verification once the session
 * holds as many counting further factors (additional factors and recovery
 * codes) as it is told to need, and nothing else.
 *
 * It stands in for MFA's requirement check, so the tests of the pending
 * adapters can leave a session pending after one further factor, or activate
 * it, without the requirement adapters.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CountsAdditionalFactors implements RequirementCheck
{
    /**
     * Constructor.
     *
     * @param  int  $needed
     */
    public function __construct(

        /** How many further factors meet an additional verification. */
        private int $needed = 1,
    ) {}

    /**
     * The requirement's additional verification, unmet while the session holds
     * fewer further factors than are needed.
     *
     * @param  \SineMacula\Laravel\Authentication\Requirements\RequirementSubject  $subject
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
     * @return \SineMacula\Laravel\Authentication\Requirements\RequirementEvaluation
     */
    #[\Override]
    public function evaluate(RequirementSubject $subject, Requirement $requirement): RequirementEvaluation
    {
        $held = count($subject->proofs(null, [ProofKind::ADDITIONAL_FACTOR, ProofKind::RECOVERY_CODE], RequirementSubject::MAX_LIMIT));

        return new RequirementEvaluation($held < $this->needed ? [RequirementKind::ADDITIONAL_VERIFICATION] : []);
    }
}
