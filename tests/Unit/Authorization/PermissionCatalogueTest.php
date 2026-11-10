<?php

declare(strict_types = 1);

namespace Tests\Unit\Authorization;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose;
use SineMacula\Laravel\Authorization\Support\PermissionDefinition;
use SineMacula\Laravel\Iam\Authorization\Enums\AdministrativeOperation;
use SineMacula\Laravel\Iam\Authorization\PermissionCatalogue;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;

/**
 * Unit tests for the catalogue of the members' administrative permissions
 * (IAM-6.9, IAM-6.10, AUTHZ-14.5): every operation of SSO's and MFA's, SSO's
 * own names reused where SSO names one, and for each of audit-log's read
 * purposes a permission to the whole purpose, to each of the suite's categories
 * and to the viewer's own activity, each name valid in `laravel-authorization`
 * and declared once, guard-agnostic, under its member's category.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PermissionCatalogue::class)]
#[CoversClass(AdministrativeOperation::class)]
final class PermissionCatalogueTest extends TestCase
{
    /** @var string `laravel-authorization`'s rule for a permission's name. */
    private const string NAME = '/^[A-Za-z0-9_\-:.*]{1,191}$/';

    /**
     * Every permission is declared once, with a valid name, guard-agnostic,
     * under its member's category.
     *
     * @return void
     */
    public function testEveryPermissionIsDeclaredOnceUnderItsMember(): void
    {
        $definitions = (new PermissionCatalogue)->permissions();
        $names       = array_map(static fn (PermissionDefinition $definition): string => $definition->name, $definitions);

        self::assertSame($names, array_values(array_unique($names)));
        self::assertCount(count(AdministrativeOperation::cases()) + 4 * 5, $definitions);

        foreach ($definitions as $definition) {
            self::assertMatchesRegularExpression(self::NAME, $definition->name);
            self::assertNull($definition->guard);
            self::assertSame(explode('.', $definition->name)[0], $definition->category);
        }
    }

    /**
     * Each operation SSO names itself is declared under SSO's own name.
     *
     * @return void
     */
    public function testSsosOwnNamesAreReused(): void
    {
        foreach (FreshnessOperation::cases() as $operation) {
            self::assertNotNull(AdministrativeOperation::tryFrom($operation->value), $operation->value);
        }
    }

    /**
     * Each operation belongs to its member.
     *
     * @return void
     */
    public function testEachOperationBelongsToItsMember(): void
    {
        self::assertSame('sso', AdministrativeOperation::SSO_LINK_REMOVE_OTHERS->member());
        self::assertSame('mfa', AdministrativeOperation::MFA_IDENTITY_RESET->member());
    }

    /**
     * MFA's administrative operations are each declared, re-enabling a factor
     * disabled at the failure ceiling (`Mfa::enableFactor()`) among them.
     *
     * @return void
     */
    public function testEveryMfaOperationIsDeclared(): void
    {
        $names = array_map(static fn (PermissionDefinition $definition): string => $definition->name, (new PermissionCatalogue)->permissions());
        $mfa   = array_values(array_filter($names, static fn (string $name): bool => str_starts_with($name, 'mfa.')));

        self::assertSame([
            'mfa.identity.reset',
            'mfa.identity.unlock',
            'mfa.factor.unlock',
            'mfa.factor.enable',
            'mfa.identity.erase',
            'mfa.requirements.manage',
        ], $mfa);
    }

    /**
     * Each read purpose has its own permissions: the whole purpose, each of the
     * suite's categories and the viewer's own activity.
     *
     * @return void
     */
    public function testEachReadPurposeHasItsOwnPermissions(): void
    {
        $names = array_map(static fn (PermissionDefinition $definition): string => $definition->name, (new PermissionCatalogue)->permissions());

        self::assertSame('audit-log.read', PermissionCatalogue::audit(ReadPurpose::READ));
        self::assertSame('audit-log.export.security', PermissionCatalogue::auditCategory(ReadPurpose::EXPORT, 'security'));
        self::assertSame('audit-log.count.own', PermissionCatalogue::auditOwn(ReadPurpose::COUNT));

        self::assertSame([
            'audit-log.verify',
            'audit-log.verify.security',
            'audit-log.verify.access_management',
            'audit-log.verify.audit',
            'audit-log.verify.own',
        ], array_slice($names, -5));
    }
}
