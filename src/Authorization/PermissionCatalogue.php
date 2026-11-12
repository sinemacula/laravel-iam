<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Authorization;

use SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose;
use SineMacula\Laravel\Authorization\Contracts\PermissionProvider;
use SineMacula\Laravel\Authorization\Support\PermissionDefinition;
use SineMacula\Laravel\Iam\Authorization\Enums\AdministrativeOperation;

/**
 * The members' administrative permissions and audit-log's read permissions, for
 * the application to list in `authorization.permission_providers`.
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
     * Every administrative operation, then each of audit-log's permissions.
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
