<?php

declare(strict_types = 1);

namespace Tests\Unit\Audit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Iam\Audit\Enums\AuthorizationActivity;

/**
 * Unit tests for the `authorization.*` codes and their definitions.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationActivity::class)]
final class AuthorizationActivityTest extends CodesTestCase
{
    /**
     * The enum under test.
     *
     * @return class-string<\SineMacula\Laravel\Iam\Audit\Enums\AuthorizationActivity>
     */
    #[\Override]
    protected static function enum(): string
    {
        return AuthorizationActivity::class;
    }

    /**
     * The reserved prefix its codes are under.
     *
     * @return list<string>
     */
    #[\Override]
    protected static function prefixes(): array
    {
        return ['authorization.'];
    }

    /**
     * Each code, with its category and what it keeps.
     *
     * @return array<string, array{0: string, 1: array<string, \SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling>}>
     */
    #[\Override]
    protected static function expected(): array
    {
        $decision   = ['action', 'resource', 'application', 'policies'];
        $definition = ['trusted', 'name', 'guard'];
        $document   = ['trusted', 'name', 'document_version', 'document_digest'];
        $excluded   = ['trusted', 'role_name', 'excluded_role', 'excluded_role_name'];
        $granted    = ['trusted', 'role_name', 'permission_name'];
        $scoped     = ['trusted', 'name', 'application', 'include_subtree'];
        $change     = 'access_management';

        return [
            'authorization.access_denied'            => ['security', self::retained(...$decision)],
            'authorization.access_allowed'           => ['security', self::retained(...$decision)],
            'authorization.break_glass_used'         => ['security', self::retained(...$decision, ...['activations'])],
            'authorization.access_previewed'         => ['security', self::retained(...$decision, ...['effect', 'reason'])],
            'authorization.role_created'             => [$change, self::retained(...$definition, ...['system'])],
            'authorization.role_updated'             => [$change, self::retained(...$definition, ...['changes'])],
            'authorization.role_deleted'             => [$change, self::retained(...$definition, ...['grantee_count', 'permission_count'])],
            'authorization.role_exclusion_declared'  => [$change, self::retained(...$excluded)],
            'authorization.role_exclusion_removed'   => [$change, self::retained(...$excluded)],
            'authorization.permission_created'       => [$change, self::retained(...$definition, ...['system'])],
            'authorization.permission_updated'       => [$change, self::retained(...$definition, ...['changes'])],
            'authorization.permission_deleted'       => [$change, self::retained(...$definition, ...['grantee_count', 'role_count'])],
            'authorization.policy_created'           => [$change, self::retained(...$document, ...['system'])],
            'authorization.policy_updated'           => [$change, self::retained(...$document, ...['changes', 'previous_document_digest'])],
            'authorization.policy_deleted'           => [$change, self::retained(...$document, ...['grantee_count'])],
            'authorization.permission_granted'       => [$change, self::retained(...$granted, ...['expires_at'])],
            'authorization.permission_revoked'       => [$change, self::retained(...$granted)],
            'authorization.role_assigned'            => [$change, self::retained(...$scoped, ...['expires_at'])],
            'authorization.role_unassigned'          => [$change, self::retained(...$scoped)],
            'authorization.permission_assigned'      => [$change, self::retained(...$scoped, ...['expires_at'])],
            'authorization.permission_unassigned'    => [$change, self::retained(...$scoped)],
            'authorization.policy_attached'          => [$change, self::retained(...$scoped, ...['expires_at'])],
            'authorization.policy_detached'          => [$change, self::retained(...$scoped)],
            'authorization.boundary_set'             => [$change, self::retained(...$scoped, ...['previous_policy'])],
            'authorization.boundary_removed'         => [$change, self::retained(...$scoped)],
            'authorization.guardrail_set'            => [$change, self::retained(...$scoped)],
            'authorization.guardrail_removed'        => [$change, self::retained(...$scoped)],
            'authorization.grant_expired'            => [$change, self::retained(...$scoped, ...['grant', 'role_name', 'permission_name', 'expired_at'])],
            'authorization.grant_expiry_changed'     => [$change, self::retained(...$scoped, ...['grant', 'role_name', 'permission_name', 'previous_expires_at', 'expires_at'])],
            'authorization.resource_policy_attached' => [$change, self::retained(...$scoped, ...['resource_type', 'resource_id'])],
            'authorization.resource_policy_detached' => [$change, self::retained(...$scoped, ...['resource_type', 'resource_id'])],
            'authorization.system_override_used'     => [$change, self::retained('trusted', 'name', 'protected_operation')],
        ];
    }
}
