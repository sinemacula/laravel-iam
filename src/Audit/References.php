<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Audit;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * The members' references read through the morph map, so every member's records
 * match; a tenant is its identifier under one type, as MFA and SSO give none.
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
     * The reference to the mapped type and the id; `null` when either is empty.
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
     * The tenant reference for the identifier; `null` when it is empty.
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
     * The morph alias of a mapped model class, or the type as it is.
     *
     * @param  string  $type
     * @return string
     */
    public static function type(string $type): string
    {
        if (!is_a($type, Model::class, true)) {
            return $type;
        }

        return (string) Relation::getMorphAlias($type);
    }
}
