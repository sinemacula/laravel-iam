<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy;

use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy;
use SineMacula\Laravel\Sso\Enforcement\Enums\ExemptionOutcome;

/**
 * The version of the tenant authentication policy's answer (IAM-4.5): one value
 * that changes whenever anything the answer depends on changes, the enforcement
 * and the exemption as much as the tenant's MFA requirement.
 *
 * `laravel-authentication` skips a session recorded at the very version it is
 * answered, so the version must change with every input of the answer, and
 * SSO's own enforcement version is not enough: it changes only with the
 * enforcing tenant's rule, not when a satisfying connection is disabled or the
 * rule's enforcing tenant changes, and an exemption has no version at all. So
 * the version is a SHA-256 digest, in hexadecimal (64 characters, exactly
 * `TenantRequirement::VERSION_MAX_LENGTH`), of every input in one canonical
 * form:
 *
 * - SSO's policy as it serialises itself: the tenant asked about, the enforcing
 *   tenant, whether a connection is required, the satisfying
 *   connections in id order and the rule's version;
 * - the exemption's outcome where the gate was asked, and that it was not;
 * - the application's rule: its version and its requirement, part by part, each
 *   with its maximum age and the minimum level's level.
 *
 * The same inputs always give the same version, so an unchanged policy never
 * judges a session again for nothing, and no input is ever dropped from it. A
 * rule that requires something but cannot be versioned (its version `null`)
 * makes the whole version `null`, which `laravel-authentication` never takes as
 * already checked: the application said it cannot tell when its answer changes,
 * so neither can this.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TenantPolicyVersion
{
    /** @var string The digest the version is made with, whose hexadecimal form is 64 characters long. */
    private const string ALGORITHM = 'sha256';

    /**
     * The version of the answer made of the enforcement, the exemption's
     * outcome where it was asked, and the application's rule, or `null` when
     * the rule requires something and cannot be versioned.
     *
     * @param  \SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy  $policy
     * @param  ?\SineMacula\Laravel\Sso\Enforcement\Enums\ExemptionOutcome  $exemption
     * @param  \SineMacula\Laravel\Iam\Tenancy\TenantMfaRule  $rule
     * @return ?string
     *
     * @throws \JsonException
     */
    public static function of(EnforcementPolicy $policy, ?ExemptionOutcome $exemption, TenantMfaRule $rule): ?string
    {
        if ($rule->version === null && !$rule->isEmpty()) {
            return null;
        }

        $inputs = [
            'enforcement' => $policy->jsonSerialize(),
            'exemption'   => $exemption?->value,
            'mfa'         => ['version' => $rule->version, 'requirement' => self::requirement($rule->requirement)],
        ];

        return hash(self::ALGORITHM, json_encode($inputs, JSON_THROW_ON_ERROR));
    }

    /**
     * The requirement in canonical form: each part it has, by name, with its
     * maximum age, and the minimum level's level; a part it lacks as `null`.
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
     * A part in canonical form: its maximum age, or `null` for a part the
     * requirement lacks.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Requirements\RequirementPart  $part
     * @return ?array<string, ?int>
     */
    private static function part(?RequirementPart $part): ?array
    {
        return $part === null ? null : ['max_age' => $part->maxAgeSeconds];
    }
}
