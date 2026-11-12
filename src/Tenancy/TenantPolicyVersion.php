<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy;

use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy;
use SineMacula\Laravel\Sso\Enforcement\Enums\ExemptionOutcome;

/**
 * The tenant policy's version: a digest of SSO's policy, the exemption and the
 * MFA tenant requirement.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TenantPolicyVersion
{
    /** @var string The digest algorithm. */
    private const string ALGORITHM = 'sha256';

    /**
     * The version of the enforcement, exemption and requirement together.
     *
     * @param  \SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy  $policy
     * @param  ?\SineMacula\Laravel\Sso\Enforcement\Enums\ExemptionOutcome  $exemption
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
     * @return string
     *
     * @throws \JsonException
     */
    public static function of(EnforcementPolicy $policy, ?ExemptionOutcome $exemption, Requirement $requirement): string
    {
        $inputs = [
            'enforcement' => $policy->jsonSerialize(),
            'exemption'   => $exemption?->value,
            'mfa'         => self::requirement($requirement),
        ];

        return hash(self::ALGORITHM, json_encode($inputs, JSON_THROW_ON_ERROR));
    }

    /**
     * The requirement in canonical form, a part it lacks as `null`.
     *
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
     * @return array<string, ?array<string, int|string|null>>
     */
    private static function requirement(Requirement $requirement): array
    {
        $level = $requirement->minimumLevel;

        return [
            'additional_verification' => self::part($requirement->additionalVerification),
            'multifactor'             => self::part($requirement->multifactor),
            'minimum_level'           => $level === null ? null : ['level' => $level->level->value, 'max_age' => $level->maxAgeSeconds],
            'phishing_resistance'     => self::part($requirement->phishingResistance),
        ];
    }

    /**
     * A part in canonical form, or `null` when absent.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Requirements\RequirementPart  $part
     * @return ?array<string, ?int>
     */
    private static function part(?RequirementPart $part): ?array
    {
        return $part === null ? null : ['max_age' => $part->maxAgeSeconds];
    }
}
