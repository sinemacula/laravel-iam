<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Tenancy;

use Illuminate\Container\Container;
use Illuminate\Contracts\Database\Query\Builder;
use Illuminate\Database\Connection;
use Illuminate\Database\ConnectionResolverInterface;
use SineMacula\Laravel\Iam\Contracts\TenantTree;

/**
 * A tenant tree held in the database, as an application's is: each tenant a row
 * of the `iam_tenant_nodes` table with its parent's id, none for a root, read
 * on the default connection, its write PDO, at every call, with nothing kept
 * from one call for the next and no lock taken.
 *
 * So a move another connection commits is seen by the next read made outside a
 * transaction that has already read, as an application's tree would be. A
 * tenant is placed or moved with `place()`, on the default connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class StoredTenantTree implements TenantTree
{
    /** @var string The table each tenant is kept in. */
    public const string TABLE = 'iam_tenant_nodes';

    /**
     * Place the tenant under the parent given, or as a root, moving it there
     * when it was placed before.
     *
     * @param  string  $tenantId
     * @param  ?string  $parentId
     * @return void
     */
    public static function place(string $tenantId, ?string $parentId = null): void
    {
        self::database()->table(self::TABLE)->updateOrInsert(['tenant_id' => $tenantId], ['parent_id' => $parentId]);
    }

    /**
     * The tenant's ancestors, nearest first, the tenant excluded.
     *
     * @param  string  $tenantId
     * @return list<string>
     */
    #[\Override]
    public function ancestors(string $tenantId): array
    {
        $ancestors = [];
        $current   = self::parentOf($tenantId);

        while ($current !== null && !in_array($current, $ancestors, true)) {
            $ancestors[] = $current;
            $current     = self::parentOf($current);
        }

        return $ancestors;
    }

    /**
     * Every tenant below the tenant, nearest first, a level at a time.
     *
     * @param  string  $tenantId
     * @return list<string>
     */
    #[\Override]
    public function descendants(string $tenantId): array
    {
        $below    = [];
        $frontier = [$tenantId];

        while ($frontier !== []) {

            $ids  = self::database()->table(self::TABLE)->useWritePdo()->whereIn('parent_id', $frontier)->orderBy('tenant_id')->pluck('tenant_id')->all();
            $next = array_values(array_filter($ids, is_string(...)));

            array_push($below, ...$next);

            $frontier = $next;
        }

        return $below;
    }

    /**
     * Whether the tenant is the ancestor given, or below it.
     *
     * @param  string  $tenantId
     * @param  string  $ancestorId
     * @return bool
     */
    #[\Override]
    public function isWithin(string $tenantId, string $ancestorId): bool
    {
        return $tenantId === $ancestorId || in_array($ancestorId, $this->ancestors($tenantId), true);
    }

    /**
     * The tenant and every tenant below it, as a query selecting their ids in
     * the `tenant_id` column.
     *
     * @param  string  $tenantId
     * @return \Illuminate\Contracts\Database\Query\Builder
     */
    #[\Override]
    public function subtree(string $tenantId): Builder
    {
        $database = self::database();
        $union    = $database->query()->selectRaw('? as ' . self::ID_COLUMN, [$tenantId]);

        foreach ($this->descendants($tenantId) as $id) {
            $union->unionAll($database->query()->selectRaw('? as ' . self::ID_COLUMN, [$id]));
        }

        return $database->query()->fromSub($union, 'subtree')->select(self::ID_COLUMN);
    }

    /**
     * The tenant's parent's id, or `null` for a root or a tenant not held.
     *
     * @param  string  $tenantId
     * @return ?string
     */
    private static function parentOf(string $tenantId): ?string
    {
        $parent = self::database()->table(self::TABLE)->useWritePdo()->where('tenant_id', $tenantId)->value('parent_id');

        return is_string($parent) ? $parent : null;
    }

    /**
     * The default connection, as it is when asked.
     *
     * @return \Illuminate\Database\Connection
     */
    private static function database(): Connection
    {
        return Container::getInstance()->make(ConnectionResolverInterface::class)->connection();
    }
}
