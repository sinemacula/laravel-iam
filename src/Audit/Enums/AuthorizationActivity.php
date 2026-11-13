<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Audit\Enums;

use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\Iam\Audit\Contracts\ListsProperties;

/**
 * The `authorization.*` codes `laravel-authorization`'s decisions and changes
 * are recorded under; changes are `access_management`, so they are kept longer.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
enum AuthorizationActivity: string implements ListsProperties
{
    case ACCESS_DENIED = 'authorization.access_denied';

    // A check of a sensitive action was allowed
    case ACCESS_ALLOWED = 'authorization.access_allowed';

    // A check was allowed by a break-glass grant
    case BREAK_GLASS_USED = 'authorization.break_glass_used';

    // A check was previewed for another principal
    case ACCESS_PREVIEWED = 'authorization.access_previewed';
    case ROLE_CREATED     = 'authorization.role_created';
    case ROLE_UPDATED     = 'authorization.role_updated';
    case ROLE_DELETED     = 'authorization.role_deleted';

    // Two roles were declared mutually exclusive
    case ROLE_EXCLUSION_DECLARED = 'authorization.role_exclusion_declared';

    // A pair of mutually exclusive roles was removed
    case ROLE_EXCLUSION_REMOVED = 'authorization.role_exclusion_removed';
    case PERMISSION_CREATED     = 'authorization.permission_created';
    case PERMISSION_UPDATED     = 'authorization.permission_updated';
    case PERMISSION_DELETED     = 'authorization.permission_deleted';
    case POLICY_CREATED         = 'authorization.policy_created';
    case POLICY_UPDATED         = 'authorization.policy_updated';
    case POLICY_DELETED         = 'authorization.policy_deleted';

    // A permission was granted to a role
    case PERMISSION_GRANTED = 'authorization.permission_granted';

    // A permission was revoked from a role
    case PERMISSION_REVOKED = 'authorization.permission_revoked';
    case ROLE_ASSIGNED      = 'authorization.role_assigned';
    case ROLE_UNASSIGNED    = 'authorization.role_unassigned';

    // A permission was assigned to a grantee
    case PERMISSION_ASSIGNED = 'authorization.permission_assigned';

    // A permission was unassigned from a grantee
    case PERMISSION_UNASSIGNED = 'authorization.permission_unassigned';

    // A policy was attached to a grantee
    case POLICY_ATTACHED = 'authorization.policy_attached';

    // A policy was detached from a grantee
    case POLICY_DETACHED          = 'authorization.policy_detached';
    case BOUNDARY_SET             = 'authorization.boundary_set';
    case BOUNDARY_REMOVED         = 'authorization.boundary_removed';
    case GUARDRAIL_SET            = 'authorization.guardrail_set';
    case GUARDRAIL_REMOVED        = 'authorization.guardrail_removed';
    case GRANT_EXPIRED            = 'authorization.grant_expired';
    case GRANT_EXPIRY_CHANGED     = 'authorization.grant_expiry_changed';
    case RESOURCE_POLICY_ATTACHED = 'authorization.resource_policy_attached';
    case RESOURCE_POLICY_DETACHED = 'authorization.resource_policy_detached';

    // A protected record was changed by a system override
    case SYSTEM_OVERRIDE_USED = 'authorization.system_override_used';

    /** @var string The category of the decisions. */
    private const string SECURITY = 'security';

    /** @var string The category of every change to who may do what. */
    private const string ACCESS_MANAGEMENT = 'access_management';

    /** @var list<string> What a decision's code keeps. */
    private const array DECISION = ['action', 'resource', 'application', 'policies'];

    /** @var list<string> What every change's code keeps of the call that made it. */
    private const array CALL = ['trusted'];

    /** @var list<string> What a code about a role or a permission keeps of it. */
    private const array DEFINITION = [...self::CALL, 'name', 'guard'];

    /** @var list<string> What a code about a policy keeps of it. */
    private const array DOCUMENT = [...self::CALL, 'name', 'document_version', 'document_digest'];

    /** @var list<string> What a code about a pair of mutually exclusive roles keeps. */
    private const array ROLE_EXCLUSION = [...self::CALL, 'role_name', 'excluded_role', 'excluded_role_name'];

    /** @var list<string> What a code about a role's permission keeps. */
    private const array ROLE_PERMISSION = [...self::CALL, 'role_name', 'permission_name'];

    /** @var list<string> What a code about a grant, a boundary or a guardrail keeps of where it holds. */
    private const array SCOPED = [...self::CALL, 'name', 'application', 'include_subtree'];

    /** @var array<string, list<string>> What each code keeps, by code. */
    private const array RETAINED = [
        self::ACCESS_DENIED->value            => self::DECISION,
        self::ACCESS_ALLOWED->value           => self::DECISION,
        self::BREAK_GLASS_USED->value         => self::DECISION,
        self::ACCESS_PREVIEWED->value         => [...self::DECISION, 'effect', 'reason'],
        self::ROLE_CREATED->value             => [...self::DEFINITION, 'system'],
        self::ROLE_UPDATED->value             => [...self::DEFINITION, 'changes'],
        self::ROLE_DELETED->value             => [...self::DEFINITION, 'grantee_count', 'permission_count'],
        self::ROLE_EXCLUSION_DECLARED->value  => self::ROLE_EXCLUSION,
        self::ROLE_EXCLUSION_REMOVED->value   => self::ROLE_EXCLUSION,
        self::PERMISSION_CREATED->value       => [...self::DEFINITION, 'system'],
        self::PERMISSION_UPDATED->value       => [...self::DEFINITION, 'changes'],
        self::PERMISSION_DELETED->value       => [...self::DEFINITION, 'grantee_count', 'role_count'],
        self::POLICY_CREATED->value           => [...self::DOCUMENT, 'system'],
        self::POLICY_UPDATED->value           => [...self::DOCUMENT, 'changes', 'previous_document_digest'],
        self::POLICY_DELETED->value           => [...self::DOCUMENT, 'grantee_count'],
        self::PERMISSION_GRANTED->value       => [...self::ROLE_PERMISSION, 'expires_at'],
        self::PERMISSION_REVOKED->value       => self::ROLE_PERMISSION,
        self::ROLE_ASSIGNED->value            => [...self::SCOPED, 'expires_at'],
        self::ROLE_UNASSIGNED->value          => self::SCOPED,
        self::PERMISSION_ASSIGNED->value      => [...self::SCOPED, 'expires_at'],
        self::PERMISSION_UNASSIGNED->value    => self::SCOPED,
        self::POLICY_ATTACHED->value          => [...self::SCOPED, 'expires_at'],
        self::POLICY_DETACHED->value          => self::SCOPED,
        self::BOUNDARY_SET->value             => [...self::SCOPED, 'previous_policy'],
        self::BOUNDARY_REMOVED->value         => self::SCOPED,
        self::GUARDRAIL_SET->value            => self::SCOPED,
        self::GUARDRAIL_REMOVED->value        => self::SCOPED,
        self::GRANT_EXPIRED->value            => [...self::SCOPED, 'grant', 'role_name', 'permission_name', 'expired_at'],
        self::GRANT_EXPIRY_CHANGED->value     => [...self::SCOPED, 'grant', 'role_name', 'permission_name', 'previous_expires_at', 'expires_at'],
        self::RESOURCE_POLICY_ATTACHED->value => [...self::SCOPED, 'resource_type', 'resource_id'],
        self::RESOURCE_POLICY_DETACHED->value => [...self::SCOPED, 'resource_type', 'resource_id'],
        self::SYSTEM_OVERRIDE_USED->value     => [...self::CALL, 'name', 'protected_operation'],
    ];

    /**
     * This case's definition, dropping every property it does not list.
     *
     * @return \SineMacula\Laravel\AuditLog\Definitions\EventDefinition
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function definition(): EventDefinition
    {
        return EventDefinition::for($this)->category($this->category())->retain(...$this->properties());
    }

    /**
     * Every property this case's code keeps.
     *
     * @return list<string>
     */
    #[\Override]
    public function properties(): array
    {
        return self::RETAINED[$this->value];
    }

    /**
     * The category this case's code is stored under.
     *
     * @return string
     */
    private function category(): string
    {
        return match ($this) {
            self::ACCESS_DENIED,
            self::ACCESS_ALLOWED,
            self::BREAK_GLASS_USED,
            self::ACCESS_PREVIEWED => self::SECURITY,
            default                => self::ACCESS_MANAGEMENT,
        };
    }
}
