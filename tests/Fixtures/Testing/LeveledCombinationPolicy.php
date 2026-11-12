<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Testing;

use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\DefaultCombinationPolicy;
use SineMacula\Laravel\Mfa\Assurance\Evaluation;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Contracts\CombinationPolicy;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\KeyProtection;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * MFA's default combination policy, except a passkey-grade proof rates AAL3.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class LeveledCombinationPolicy implements CombinationPolicy
{
    /**
     * As the default answers.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $firstFactor
     * @param  \SineMacula\Laravel\Mfa\Assurance\Channel  $factor
     * @return bool
     */
    #[\Override]
    public function accepts(Proof $firstFactor, Channel $factor): bool
    {
        return (new DefaultCombinationPolicy)->accepts($firstFactor, $factor);
    }

    /**
     * The default's evaluation, at AAL3 when a proof observed everything.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  ...$proofs
     * @return \SineMacula\Laravel\Mfa\Assurance\Evaluation
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function evaluate(Requirement $requirement, Proof ...$proofs): Evaluation
    {
        $evaluation = (new DefaultCombinationPolicy)->evaluate($requirement, ...$proofs);

        foreach ($proofs as $proof) {

            if (self::observedAll($proof->properties)) {
                return new Evaluation(
                    accepted: true,
                    multifactor: true,
                    level: AssuranceLevel::AAL3,
                    phishingResistant: true,
                    restricted: false,
                    amr: $evaluation->amr,
                    met: [...$evaluation->met, ...$evaluation->unmet],
                    unmet: [],
                    multifactorAt: $evaluation->multifactorAt ?? $proof->provedAt,
                );
            }
        }

        return $evaluation;
    }

    /**
     * Whether the proof observed every property AAL3 takes here.
     *
     * @param  \SineMacula\Laravel\Mfa\Assurance\ObservedProperties  $properties
     * @return bool
     */
    private static function observedAll(ObservedProperties $properties): bool
    {
        return $properties->userPresence       === true
            && $properties->userVerification   === true
            && $properties->phishingResistance === true
            && $properties->keyProtection      === KeyProtection::HARDWARE;
    }
}
