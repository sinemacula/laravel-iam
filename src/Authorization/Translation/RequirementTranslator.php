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
 * Translates `laravel-authorization`'s authentication requirement into MFA's,
 * and MFA's evaluation back into `laravel-authorization`'s result.
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
     * MFA's evaluation as `laravel-authorization`'s result.
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
     * The MFA level named, refusing `unclassified` and unknown names.
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
