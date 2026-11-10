<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Authorization;

use SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose;
use SineMacula\Laravel\Authorization\Contracts\PermissionProvider;
use SineMacula\Laravel\Authorization\Support\PermissionDefinition;
use SineMacula\Laravel\Iam\Authorization\Enums\AdministrativeOperation;

/**
 * The optional catalogue of the members' administrative permissions (IAM-6.9,
 * AUTHZ-14.5): SSO's and MFA's administrative operations
 * (`Enums\AdministrativeOperation`), and audit-log's reads of the trail, one
 * set for each purpose audit-log reads for (`ReadPurpose`: `read`, `count`,
 * `export`, `verify`), which the audit access policy answers from
 * (`AuditAccessPolicyAdapter`, IAM-6.10).
 *
 * For each purpose:
 *
 * - `audit-log.{purpose}` reaches every category of the trail;
 * - `audit-log.{purpose}.{category}` reaches one of the categories the suite
 *   records under (`CATEGORIES`): `security` (sign-ins, sessions, MFA, SSO's
 *   flows, access decisions), `access_management` (changes to who may do what)
 *   and `audit` (audit-log's own records of who read the trail);
 * - `audit-log.{purpose}.own` reaches only the viewer's own activity.
 *
 * The application opts in by naming this class in `laravel-authorization`'s
 * `authorization.permission_providers`; `authorization:sync` then writes the
 * permissions, so they can be granted, named in a policy and checked through
 * `laravel-authorization` and Laravel's Gate. Every name is guard-agnostic and
 * carries the member it belongs to as its category. The members check nothing
 * themselves, so the application checks one of these before each operation
 * (`AdministrativeCheck`), and grants the audit permissions for the access
 * policy to read.
 *
 * Pure: it reads nothing and keeps nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final readonly class PermissionCatalogue implements PermissionProvider
{
    /** @var string The prefix of audit-log's permissions, and the category they are declared under. */
    public const string AUDIT_LOG = 'audit-log';

    /** @var string The narrowing of a purpose to the viewer's own activity. */
    public const string OWN = 'own';

    /** @var list<string> The categories the suite records under, each with its own permission for every purpose. */
    public const array CATEGORIES = ['security', 'access_management', 'audit'];

    /**
     * Every permission the catalogue declares: each administrative operation,
     * then each of audit-log's.
     *
     * @return list<\SineMacula\Laravel\Authorization\Support\PermissionDefinition>
     */
    #[\Override]
    public function permissions(): array
    {
        $operations = array_map(
            static fn (AdministrativeOperation $operation): PermissionDefinition => new PermissionDefinition($operation->value, category: $operation->member()),
            AdministrativeOperation::cases(),
        );

        return [...$operations, ...array_map(static fn (string $name): PermissionDefinition => new PermissionDefinition($name, category: self::AUDIT_LOG), self::auditNames())];
    }

    /**
     * The permission to the whole of the purpose.
     *
     * @param  \SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose  $purpose
     * @return string
     */
    public static function audit(ReadPurpose $purpose): string
    {
        return self::AUDIT_LOG . '.' . $purpose->value;
    }

    /**
     * The permission to the purpose over one of the suite's categories.
     *
     * @param  \SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose  $purpose
     * @param  string  $category
     * @return string
     */
    public static function auditCategory(ReadPurpose $purpose, string $category): string
    {
        return self::audit($purpose) . '.' . $category;
    }

    /**
     * The permission to the purpose over the viewer's own activity.
     *
     * @param  \SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose  $purpose
     * @return string
     */
    public static function auditOwn(ReadPurpose $purpose): string
    {
        return self::audit($purpose) . '.' . self::OWN;
    }

    /**
     * Every one of audit-log's permissions, purpose by purpose.
     *
     * @return list<string>
     */
    private static function auditNames(): array
    {
        $names = [];

        foreach (ReadPurpose::cases() as $purpose) {
            $names[] = self::audit($purpose);

            foreach (self::CATEGORIES as $category) {
                $names[] = self::auditCategory($purpose, $category);
            }

            $names[] = self::auditOwn($purpose);
        }

        return $names;
    }
}
