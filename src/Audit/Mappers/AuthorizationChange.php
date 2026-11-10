<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Audit\Mappers;

use SineMacula\Laravel\Authorization\Events\Identity\PermissionExpired;
use SineMacula\Laravel\Authorization\Events\Identity\PermissionExpiryChanged;
use SineMacula\Laravel\Authorization\Events\Identity\PolicyExpired;
use SineMacula\Laravel\Authorization\Events\Identity\PolicyExpiryChanged;
use SineMacula\Laravel\Authorization\Events\Identity\RoleExpired;
use SineMacula\Laravel\Authorization\Events\Identity\RoleExpiryChanged;
use SineMacula\Laravel\Authorization\Events\Role\PermissionExpired as RolePermissionExpired;
use SineMacula\Laravel\Authorization\Events\Role\PermissionExpiryChanged as RolePermissionExpiryChanged;
use SineMacula\Laravel\Authorization\Support\DocumentDigest;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Iam\Audit\References;

/**
 * What one of `laravel-authorization`'s changes says, read from the event alone
 * (IAM-9.2, IAM-9.4): the call that made it, what it changed, the tenant it
 * holds in, the properties it describes itself with, and the grantees a
 * deletion took a grant from.
 *
 * Its changes share their fields by name, not by a contract, so each is read by
 * name: what changed is the first of the grantee, the role, the permission, the
 * policy and the record the event names, so a grant is the grantee's, a role's
 * permission the role's and a guardrail or resource policy the policy's; the
 * tenant is the grant's scope's, or the record's owner's; and each property is
 * the field of that name, translated to the record's (a reference by its id, a
 * list by its count, an update by the names of the fields it changed, a
 * policy's document by its version and digest, a resource's type through the
 * morph map). The code's definition decides which are kept, so a field a code
 * does not list is never recorded.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AuthorizationChange
{
    /** @var list<string> The fields what changed is read from, in the order they are tried. */
    private const array SUBJECTS = ['grantee', 'role', 'permission', 'policy', 'record'];

    /** @var array<string, string> The fields kept as they are, by the property they are kept as. */
    private const array VALUES = [
        'name'                => 'name',
        'guard'               => 'guard',
        'system'              => 'isSystem',
        'role_name'           => 'roleName',
        'permission_name'     => 'permissionName',
        'expires_at'          => 'expiresAt',
        'expired_at'          => 'expiredAt',
        'previous_expires_at' => 'previousExpiresAt',
        'protected_operation' => 'protectedOperation',
        'resource_id'         => 'resourceId',
    ];

    /** @var array<string, string> The lists kept by their count, by the property they are kept as. */
    private const array COUNTS = [
        'grantee_count'    => 'grantees',
        'permission_count' => 'permissions',
        'role_count'       => 'roles',
    ];

    /** @var array<class-string, string> The kind of grant each expiry, or change to one, is about. */
    private const array GRANTS = [
        RoleExpired::class                 => 'role',
        RoleExpiryChanged::class           => 'role',
        PermissionExpired::class           => 'permission',
        PermissionExpiryChanged::class     => 'permission',
        PolicyExpired::class               => 'policy',
        PolicyExpiryChanged::class         => 'policy',
        RolePermissionExpired::class       => 'role_permission',
        RolePermissionExpiryChanged::class => 'role_permission',
    ];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @param  ?\SineMacula\Laravel\Authorization\Support\Reference  $subject
     * @param  ?\SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @param  array<string, mixed>  $properties
     * @param  list<\SineMacula\Laravel\Authorization\Support\Reference>  $grantees
     */
    public function __construct(

        /** The call that made the change. */
        public Operation $operation,

        /** What the change changed. */
        public ?Reference $subject,

        /** The tenant the change holds in; `null` for the platform. */
        public ?Reference $tenant,

        /** What the change describes itself with, none of it `null`. */
        public array $properties,

        /** Every grantee a deletion took a grant from; none for any other change. */
        public array $grantees,
    ) {}

    /**
     * What the event says, or `null` for an event that is no change.
     *
     * @param  object  $event
     * @return ?self
     */
    public static function of(object $event): ?self
    {
        $fields    = get_object_vars($event);
        $operation = $fields['operation'] ?? null;

        if (!$operation instanceof Operation) {
            return null;
        }

        $scope = ($fields['scope'] ?? null) instanceof GrantScope ? $fields['scope'] : null;

        return new self(
            $operation,
            self::subjectOf($fields),
            $scope === null ? self::reference($fields, 'tenant') : $scope->tenant,
            self::properties($event, $fields, $scope),
            self::grantees($fields),
        );
    }

    /**
     * What the change changed: the first reference the event names of the
     * grantee, the role, the permission, the policy and the record.
     *
     * @param  array<string, mixed>  $fields
     * @return ?\SineMacula\Laravel\Authorization\Support\Reference
     */
    private static function subjectOf(array $fields): ?Reference
    {
        foreach (self::SUBJECTS as $field) {
            $reference = self::reference($fields, $field);

            if ($reference !== null) {
                return $reference;
            }
        }

        return null;
    }

    /**
     * The properties the change describes itself with, less any it does not
     * have.
     *
     * @param  object  $event
     * @param  array<string, mixed>  $fields
     * @param  ?\SineMacula\Laravel\Authorization\Support\GrantScope  $scope
     * @return array<string, mixed>
     */
    private static function properties(object $event, array $fields, ?GrantScope $scope): array
    {
        $properties = [
            'grant'           => self::GRANTS[$event::class] ?? null,
            'application'     => $scope?->application,
            'include_subtree' => $scope?->includeSubtree,
            ...self::translated($fields),
        ];

        foreach (self::VALUES as $property => $field) {
            $properties[$property] = $fields[$field] ?? null;
        }

        foreach (self::COUNTS as $property => $field) {
            $properties[$property] = is_array($fields[$field] ?? null) ? count($fields[$field]) : null;
        }

        return array_filter($properties, static fn (mixed $value): bool => $value !== null);
    }

    /**
     * The fields kept in a form of the record's own: a resource's type through
     * the morph map, a reference by its id, an update by the names of the
     * fields it changed, and a policy's document by its version and digest.
     *
     * @param  array<string, mixed>  $fields
     * @return array<string, mixed>
     */
    private static function translated(array $fields): array
    {
        $type     = $fields['resourceType'] ?? null;
        $document = self::document($fields, 'document');

        return [
            'resource_type'            => is_string($type) ? References::type($type) : null,
            'previous_policy_id'       => self::reference($fields, 'previous')?->id,
            'changes'                  => self::changes($fields['changes'] ?? null),
            'document_version'         => $document?->version,
            'document_digest'          => $document?->digest,
            'previous_document_digest' => self::document($fields, 'previousDocument')?->digest,
        ];
    }

    /**
     * Every grantee a deletion took a grant from.
     *
     * @param  array<string, mixed>  $fields
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference>
     */
    private static function grantees(array $fields): array
    {
        $grantees = $fields['grantees'] ?? [];

        return is_array($grantees) ? array_values(array_filter($grantees, static fn (mixed $grantee): bool => $grantee instanceof Reference)) : [];
    }

    /**
     * The names of the fields an update changed, never their values, in
     * order; `null` for a change that is no update.
     *
     * @param  mixed  $changes
     * @return ?list<string>
     */
    private static function changes(mixed $changes): ?array
    {
        if (!is_array($changes)) {
            return null;
        }

        $names = [];

        foreach ($changes as $side) {
            $names = [...$names, ...array_map(strval(...), array_keys(is_array($side) ? $side : []))];
        }

        $names = array_unique($names);

        sort($names, SORT_STRING);

        return $names;
    }

    /**
     * The reference the field holds, or `null` when it holds none.
     *
     * @param  array<string, mixed>  $fields
     * @param  string  $field
     * @return ?\SineMacula\Laravel\Authorization\Support\Reference
     */
    private static function reference(array $fields, string $field): ?Reference
    {
        $reference = $fields[$field] ?? null;

        return $reference instanceof Reference ? $reference : null;
    }

    /**
     * The document digest the field holds, or `null` when it holds none.
     *
     * @param  array<string, mixed>  $fields
     * @param  string  $field
     * @return ?\SineMacula\Laravel\Authorization\Support\DocumentDigest
     */
    private static function document(array $fields, string $field): ?DocumentDigest
    {
        $document = $fields[$field] ?? null;

        return $document instanceof DocumentDigest ? $document : null;
    }
}
