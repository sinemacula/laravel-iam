<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Authorization\Translation;

use SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement;
use SineMacula\Laravel\Authorization\Evaluation\RequirementResult;
use SineMacula\Laravel\Mfa\Assurance\Evaluation;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\RequirementPart;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * Translates an authentication requirement a `laravel-authorization` policy
 * statement states into MFA's, and MFA's evaluation of it back into
 * `laravel-authorization`'s result (IAM-6.3, IAM-6.4).
 *
 * The parts cross one for one, each with its maximum age: an additional
 * verification, multifactor authentication, phishing resistance
 * (`phishing_resistant`, MFA's `phishing_resistance`) and an assurance level of
 * at least the one named (`assurance_level`, MFA's `minimum_level`). The level
 * is one of MFA's (`aal1`, `aal2`, `aal3`), named exactly as MFA names it; any
 * other, `unclassified` among them, which meets no level, cannot be judged, and
 * is refused with an `InvalidArgumentException` rather than read as the nearest
 * level, so a statement naming it is undecidable. What each part means, and
 * what meets it, is MFA's.
 *
 * MFA's evaluation crosses back as met, with the instant it stops being met
 * when a maximum age bounds it, or as unmet, with the parts it leaves unmet,
 * named as `laravel-authorization` names them and in its order.
 *
 * It reads and keeps nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RequirementTranslator
{
    /** @var array<string, \SineMacula\Laravel\Mfa\Enums\RequirementPart> Each part `laravel-authorization` names, with MFA's part, in `laravel-authorization`'s order. */
    private const array PARTS = [
        'additional_verification'                  => RequirementPart::ADDITIONAL_VERIFICATION,
        'multifactor'                              => RequirementPart::MULTIFACTOR,
        'phishing_resistant'                       => RequirementPart::PHISHING_RESISTANCE,
        AuthenticationRequirement::ASSURANCE_LEVEL => RequirementPart::MINIMUM_LEVEL,
    ];

    /**
     * The requirement as MFA's, part for part and age for age.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement  $requirement
     * @return \SineMacula\Laravel\Mfa\Requirements\Requirement
     *
     * @throws \InvalidArgumentException
     */
    public function toMfa(AuthenticationRequirement $requirement): Requirement
    {
        $translated = Requirement::none();

        foreach ($requirement->parts as $part => $maxAge) {
            $translated = match ($part) {
                'additional_verification' => $translated->withAdditionalVerification($maxAge),
                'multifactor'             => $translated->withMultifactor($maxAge),
                'phishing_resistant'      => $translated->withPhishingResistance($maxAge),
                default                   => $translated->withMinimumLevel(self::level($requirement->minimumLevel), $maxAge),
            };
        }

        return $translated;
    }

    /**
     * MFA's evaluation as `laravel-authorization`'s result: met, until the
     * instant a maximum age bounds it to, or unmet, with the parts it leaves
     * unmet.
     *
     * @param  \SineMacula\Laravel\Mfa\Assurance\Evaluation  $evaluation
     * @return \SineMacula\Laravel\Authorization\Evaluation\RequirementResult
     */
    public function result(Evaluation $evaluation): RequirementResult
    {
        if ($evaluation->meetsRequirement()) {
            return RequirementResult::met($evaluation->metUntil);
        }

        $unmet = array_filter(self::PARTS, static fn (RequirementPart $part): bool => in_array($part, $evaluation->unmet, true));

        return RequirementResult::unmet(array_keys($unmet));
    }

    /**
     * MFA's level the requirement names, exactly as MFA names it.
     *
     * @param  ?string  $level
     * @return \SineMacula\Laravel\Mfa\Enums\AssuranceLevel
     *
     * @throws \InvalidArgumentException
     */
    private static function level(?string $level): AssuranceLevel
    {
        $translated = $level === null ? null : AssuranceLevel::tryFrom($level);

        if ($translated === null || $translated === AssuranceLevel::UNCLASSIFIED) {
            throw new \InvalidArgumentException(sprintf('The assurance level [%s] is not one MFA can require: name aal1, aal2 or aal3.', $level ?? ''));
        }

        return $translated;
    }
}
