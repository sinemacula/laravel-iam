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
        $level = $requirement->minimumLevel === null ? null : $this->level($requirement->minimumLevel);

        return new AuthenticationRequirement(
            self::partOf($requirement, MfaRequirementPart::ADDITIONAL_VERIFICATION),
            self::partOf($requirement, MfaRequirementPart::MULTIFACTOR),
            $level === null ? null : new LevelRequirement($level, $requirement->maxAge(MfaRequirementPart::MINIMUM_LEVEL)),
            self::partOf($requirement, MfaRequirementPart::PHISHING_RESISTANCE),
        );
    }

    /**
     * The parts MFA's evaluation leaves unmet.
     *
     * @param  \SineMacula\Laravel\Mfa\Assurance\Evaluation  $evaluation
     * @return \SineMacula\Laravel\Authentication\Requirements\RequirementEvaluation
     */
    public function evaluation(Evaluation $evaluation): RequirementEvaluation
    {
        return new RequirementEvaluation(array_map($this->kind(...), $evaluation->unmet));
    }

    /**
     * A freshness requirement per part of MFA's, each needing a maximum age.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @return list<\SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement>
     *
     * @throws \InvalidArgumentException
     */
    public function toFreshnessParts(MfaRequirement $requirement): array
    {
        return array_map(
            static fn (MfaRequirementPart $part): FreshnessRequirement => self::freshnessOf($part, $requirement->maxAge($part) ?? throw self::unbounded($part)),
            $requirement->parts(),
        );
    }

    /**
     * One freshness requirement holding every part, each held to a day at most.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @return ?\SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement
     *
     * @throws \InvalidArgumentException
     */
    public function toFreshness(MfaRequirement $requirement): ?FreshnessRequirement
    {
        if ($requirement->isEmpty()) {
            return null;
        }

        if ($requirement->asks(MfaRequirementPart::MINIMUM_LEVEL)) {
            throw self::noMinimumLevel();
        }

        $ages = array_map(
            static fn (MfaRequirementPart $part): int => $requirement->maxAge($part) ?? FreshnessRequirement::MAX_AGE_SECONDS,
            $requirement->parts(),
        );

        return new FreshnessRequirement(
            min(FreshnessRequirement::MAX_AGE_SECONDS, ...$ages),
            $requirement->asks(MfaRequirementPart::ADDITIONAL_VERIFICATION) ? self::ADDITIONAL_VERIFICATIONS : ProofKind::cases(),
            $requirement->asks(MfaRequirementPart::MULTIFACTOR),
            $requirement->asks(MfaRequirementPart::PHISHING_RESISTANCE),
        );
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
     * A freshness requirement for one part within the age.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\RequirementPart  $part
     * @param  int  $maxAge
     * @return \SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement
     *
     * @throws \InvalidArgumentException
     */
    private static function freshnessOf(MfaRequirementPart $part, int $maxAge): FreshnessRequirement
    {
        return match ($part) {
            MfaRequirementPart::ADDITIONAL_VERIFICATION => new FreshnessRequirement($maxAge, self::ADDITIONAL_VERIFICATIONS),
            MfaRequirementPart::MULTIFACTOR             => new FreshnessRequirement($maxAge, ProofKind::cases(), multifactor: true),
            MfaRequirementPart::PHISHING_RESISTANCE     => new FreshnessRequirement($maxAge, ProofKind::cases(), phishingResistant: true),
            MfaRequirementPart::MINIMUM_LEVEL           => throw self::noMinimumLevel(),
        };
    }

    /**
     * The refusal of a part asked as freshness with no maximum age.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\RequirementPart  $part
     * @return \InvalidArgumentException
     */
    private static function unbounded(MfaRequirementPart $part): \InvalidArgumentException
    {
        return new \InvalidArgumentException(sprintf('A freshness requirement\'s [%s] part must have a maximum age.', $part->value));
    }

    /**
     * The refusal of a minimum assurance level asked as freshness.
     *
     * @return \InvalidArgumentException
     */
    private static function noMinimumLevel(): \InvalidArgumentException
    {
        $message = 'laravel-authentication\'s freshness cannot hold a session to a minimum assurance level, which its proofs do not record:'
            . ' configure the operation\'s freshness without one, or bind a gate of your own that judges it.';

        return new \InvalidArgumentException($message);
    }

    /**
     * `laravel-authentication`'s part, if MFA's requirement asks for it.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  \SineMacula\Laravel\Mfa\Enums\RequirementPart  $part
     * @return ?\SineMacula\Laravel\Authentication\Requirements\RequirementPart
     *
     * @throws \InvalidArgumentException
     */
    private static function partOf(MfaRequirement $requirement, MfaRequirementPart $part): ?AuthenticationRequirementPart
    {
        return $requirement->asks($part) ? new AuthenticationRequirementPart($requirement->maxAge($part)) : null;
    }
}
