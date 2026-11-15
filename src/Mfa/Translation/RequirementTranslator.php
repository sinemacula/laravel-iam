<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa\Translation;

use SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Requirements\Enums\AssuranceLevel as AuthenticationLevel;
use SineMacula\Laravel\Authentication\Requirements\Enums\RequirementKind;
use SineMacula\Laravel\Authentication\Requirements\LevelRequirement;
use SineMacula\Laravel\Authentication\Requirements\Requirement as AuthenticationRequirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementEvaluation;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart as AuthenticationRequirementPart;
use SineMacula\Laravel\Mfa\Assurance\Evaluation;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel as MfaLevel;
use SineMacula\Laravel\Mfa\Enums\RequirementPart as MfaRequirementPart;
use SineMacula\Laravel\Mfa\Requirements\Requirement as MfaRequirement;

/**
 * Translates requirements, parts, levels and evaluations between
 * `laravel-authentication` and MFA.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RequirementTranslator
{
    /** @var list<\SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind> The proofs that are an additional verification: a further factor or a recovery code. */
    public const array ADDITIONAL_VERIFICATIONS = [ProofKind::ADDITIONAL_FACTOR, ProofKind::RECOVERY_CODE];

    /**
     * MFA's requirement for `laravel-authentication`'s.
     *
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
     * @return \SineMacula\Laravel\Mfa\Requirements\Requirement
     *
     * @throws \InvalidArgumentException
     */
    public function toMfa(AuthenticationRequirement $requirement): MfaRequirement
    {
        $translated = MfaRequirement::none();

        if ($requirement->additionalVerification !== null) {
            $translated = $translated->withAdditionalVerification($requirement->additionalVerification->maxAgeSeconds);
        }

        if ($requirement->multifactor !== null) {
            $translated = $translated->withMultifactor($requirement->multifactor->maxAgeSeconds);
        }

        if ($requirement->minimumLevel !== null) {
            $translated = $translated->withMinimumLevel($this->toMfaLevel($requirement->minimumLevel->level), $requirement->minimumLevel->maxAgeSeconds);
        }

        if ($requirement->phishingResistance !== null) {
            $translated = $translated->withPhishingResistance($requirement->phishingResistance->maxAgeSeconds);
        }

        return $translated;
    }

    /**
     * `laravel-authentication`'s requirement for MFA's.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
     *
     * @throws \InvalidArgumentException
     */
    public function toAuthentication(MfaRequirement $requirement): AuthenticationRequirement
    {
        return $this->translated($requirement, $requirement->maxAge(...));
    }

    /**
     * `laravel-authentication`'s requirement for a factor change's, each part
     * held to a day at most.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
     *
     * @throws \InvalidArgumentException
     */
    public function toFactorChange(MfaRequirement $requirement): AuthenticationRequirement
    {
        $day = FreshnessRequirement::MAX_AGE_SECONDS;

        return $this->translated($requirement, static fn (MfaRequirementPart $part): int => min($requirement->maxAge($part) ?? $day, $day));
    }

    /**
     * `laravel-authentication`'s requirement for MFA's freshness requirement,
     * each part within a day.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
     *
     * @throws \InvalidArgumentException
     */
    public function toBoundedAuthentication(MfaRequirement $requirement): AuthenticationRequirement
    {
        foreach ($requirement->parts() as $part) {

            $maxAge = $requirement->maxAge($part);

            if ($maxAge === null || $maxAge > FreshnessRequirement::MAX_AGE_SECONDS) {
                $message = sprintf('A freshness requirement\'s [%s] part must have a maximum age from 1 to %d seconds.', $part->value, FreshnessRequirement::MAX_AGE_SECONDS);

                throw new \InvalidArgumentException($message);
            }
        }

        return $this->toAuthentication($requirement);
    }

    /**
     * The parts MFA's evaluation leaves unmet, and until when a met one holds.
     *
     * @param  \SineMacula\Laravel\Mfa\Assurance\Evaluation  $evaluation
     * @return \SineMacula\Laravel\Authentication\Requirements\RequirementEvaluation
     *
     * @throws \InvalidArgumentException
     */
    public function evaluation(Evaluation $evaluation): RequirementEvaluation
    {
        return new RequirementEvaluation(array_map($this->kind(...), $evaluation->unmet), $evaluation->metUntil);
    }

    /**
     * MFA's requirement for the freshness parts it can express.
     *
     * @param  \SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement  $freshness
     * @return ?\SineMacula\Laravel\Mfa\Requirements\Requirement
     *
     * @throws \InvalidArgumentException
     */
    public function fromFreshness(FreshnessRequirement $freshness): ?MfaRequirement
    {
        $requirement = MfaRequirement::none();

        if (array_diff(array_column($freshness->proofs, 'value'), array_column(self::ADDITIONAL_VERIFICATIONS, 'value')) === []) {
            $requirement = $requirement->withAdditionalVerification($freshness->maxAgeSeconds);
        }

        if ($freshness->multifactor) {
            $requirement = $requirement->withMultifactor($freshness->maxAgeSeconds);
        }

        if ($freshness->phishingResistant) {
            $requirement = $requirement->withPhishingResistance($freshness->maxAgeSeconds);
        }

        return $requirement->isEmpty() ? null : $requirement;
    }

    /**
     * `laravel-authentication`'s level for MFA's; `unclassified` is none.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $level
     * @return ?\SineMacula\Laravel\Authentication\Requirements\Enums\AssuranceLevel
     */
    public function level(MfaLevel $level): ?AuthenticationLevel
    {
        return match ($level) {
            MfaLevel::AAL1         => AuthenticationLevel::AAL1,
            MfaLevel::AAL2         => AuthenticationLevel::AAL2,
            MfaLevel::AAL3         => AuthenticationLevel::AAL3,
            MfaLevel::UNCLASSIFIED => null,
        };
    }

    /**
     * MFA's level for `laravel-authentication`'s.
     *
     * @param  \SineMacula\Laravel\Authentication\Requirements\Enums\AssuranceLevel  $level
     * @return \SineMacula\Laravel\Mfa\Enums\AssuranceLevel
     */
    public function toMfaLevel(AuthenticationLevel $level): MfaLevel
    {
        return match ($level) {
            AuthenticationLevel::AAL1 => MfaLevel::AAL1,
            AuthenticationLevel::AAL2 => MfaLevel::AAL2,
            AuthenticationLevel::AAL3 => MfaLevel::AAL3,
        };
    }

    /**
     * `laravel-authentication`'s kind of part for MFA's.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\RequirementPart  $part
     * @return \SineMacula\Laravel\Authentication\Requirements\Enums\RequirementKind
     */
    public function kind(MfaRequirementPart $part): RequirementKind
    {
        return match ($part) {
            MfaRequirementPart::ADDITIONAL_VERIFICATION => RequirementKind::ADDITIONAL_VERIFICATION,
            MfaRequirementPart::MULTIFACTOR             => RequirementKind::MULTIFACTOR,
            MfaRequirementPart::MINIMUM_LEVEL           => RequirementKind::MINIMUM_LEVEL,
            MfaRequirementPart::PHISHING_RESISTANCE     => RequirementKind::PHISHING_RESISTANCE,
        };
    }

    /**
     * MFA's part for `laravel-authentication`'s kind of part.
     *
     * @param  \SineMacula\Laravel\Authentication\Requirements\Enums\RequirementKind  $kind
     * @return \SineMacula\Laravel\Mfa\Enums\RequirementPart
     */
    public function part(RequirementKind $kind): MfaRequirementPart
    {
        return match ($kind) {
            RequirementKind::ADDITIONAL_VERIFICATION => MfaRequirementPart::ADDITIONAL_VERIFICATION,
            RequirementKind::MULTIFACTOR             => MfaRequirementPart::MULTIFACTOR,
            RequirementKind::MINIMUM_LEVEL           => MfaRequirementPart::MINIMUM_LEVEL,
            RequirementKind::PHISHING_RESISTANCE     => MfaRequirementPart::PHISHING_RESISTANCE,
        };
    }

    /**
     * `laravel-authentication`'s requirement for MFA's, at the ages given.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  \Closure(\SineMacula\Laravel\Mfa\Enums\RequirementPart): ?int  $maxAge
     * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
     *
     * @throws \InvalidArgumentException
     */
    private function translated(MfaRequirement $requirement, \Closure $maxAge): AuthenticationRequirement
    {
        $part  = static fn (MfaRequirementPart $part): ?AuthenticationRequirementPart => $requirement->asks($part) ? new AuthenticationRequirementPart($maxAge($part)) : null;
        $level = $requirement->minimumLevel === null ? null : $this->level($requirement->minimumLevel);

        return new AuthenticationRequirement(
            $part(MfaRequirementPart::ADDITIONAL_VERIFICATION),
            $part(MfaRequirementPart::MULTIFACTOR),
            $level === null ? null : new LevelRequirement($level, $maxAge(MfaRequirementPart::MINIMUM_LEVEL)),
            $part(MfaRequirementPart::PHISHING_RESISTANCE),
        );
    }
}
