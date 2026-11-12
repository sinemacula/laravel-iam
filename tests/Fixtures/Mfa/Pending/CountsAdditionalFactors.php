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
 * A requirement check met once the session holds enough further factors.
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
     * The additional verification, unmet while too few factors are held.
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
