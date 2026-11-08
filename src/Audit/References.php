<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Audit;

use Illuminate\Database\Eloquent\Relations\Relation;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * The references the mappers name actors, subjects, principals and tenants by,
 * translated from each member's keys so the records of every member match
 * (IAM-9.5): `laravel-authentication`'s `identity_type` and `principal_type`,
 * MFA's `identity_type`, `principal_type` and actor type, and SSO's
 * `identity_morph_class`, `acting_identity_morph_class` and
 * `principal_morph_class` are each a morph class, or a class name where a model
 * is not in the morph map, and each is read through the application's morph
 * map: a class the map names an alias for is referred to by that alias, so a
 * member that wrote the class name and one that wrote the alias name the same
 * model alike. Anything else (an alias, a name of the application's own) is
 * kept as it is. A model class of a member's own (SSO's connection, domain or
 * key) is referred to the same way.
 *
 * A tenant is named by its opaque identifier alone, under the one type `tenant`
 * (`TENANT_TYPE`): every member names the active tenant by
 * `laravel-authentication`'s tenant identifier (`getTenantIdentifier()`), which
 * need not be any model's key, while only some of `laravel-authentication`'s
 * contexts give it a type, and MFA's (`tenant_id`) and SSO's (`tenant_id`,
 * `connection_tenant_id`) never do. One type for all of them is what lets a
 * tenant's records match whichever member reported them; the identifier is kept
 * exactly.
 *
 * A part that is `null` or empty is no reference. The type and id are given to
 * audit-log as they are, which refuses either beyond 191 characters, so a
 * reference that cannot be recorded faithfully fails the capture, contained and
 * reported as `AuditCaptureFailed`, rather than be recorded as another. Nothing
 * is queried and nothing is kept: the morph map is the only state read.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class References
{
    /** @var string The one type every tenant is referred to by. */
    public const string TENANT_TYPE = 'tenant';

    /**
     * The reference to the type, read through the morph map, and the id; `null`
     * when either is missing or empty.
     *
     * @param  ?string  $type
     * @param  int|string|null  $id
     * @return ?\SineMacula\Laravel\AuditLog\Records\Reference
     *
     * @throws \InvalidArgumentException
     */
    public static function of(?string $type, int|string|null $id): ?Reference
    {
        if ($type === null || $type === '' || $id === null || $id === '') {
            return null;
        }

        return Reference::of(self::type($type), $id);
    }

    /**
     * The reference to the tenant the opaque identifier names; `null` when it
     * is missing or empty.
     *
     * @param  int|string|null  $tenantId
     * @return ?\SineMacula\Laravel\AuditLog\Records\Reference
     *
     * @throws \InvalidArgumentException
     */
    public static function tenant(int|string|null $tenantId): ?Reference
    {
        return $tenantId === null || $tenantId === '' ? null : Reference::of(self::TENANT_TYPE, $tenantId);
    }

    /**
     * The type as the morph map names it: the alias of a mapped class, and any
     * other type as it is.
     *
     * @param  string  $type
     * @return string
     */
    public static function type(string $type): string
    {
        return (string) Relation::getMorphAlias($type);
    }
}
