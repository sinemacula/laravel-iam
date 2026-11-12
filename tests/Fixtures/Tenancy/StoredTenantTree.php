<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Tenancy;

use Illuminate\Container\Container;
use Illuminate\Contracts\Database\Query\Builder;
use Illuminate\Database\Connection;
use Illuminate\Database\ConnectionResolverInterface;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Fixtures\Resolvers\ClaimedTenant;

/**
 * A tenant tree in the `iam_tenant_nodes` table, read afresh each call.
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
     * Place the tenant under the parent, or as a root.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|string  $tenant
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|string|null  $parent
     * @return void
     */
    public static function place(Reference|string $tenant, Reference|string|null $parent = null): void
    {
        $tenant = self::reference($tenant);
        $parent = $parent === null ? null : self::reference($parent);

        self::database()->table(self::TABLE)->updateOrInsert(
            ['tenant_type' => $tenant->type, 'tenant_id' => $tenant->id],
            ['parent_type' => $parent?->type, 'parent_id' => $parent?->id],
        );
    }

    /**
     * Take the tenant out of the tree, its children placed under its parent.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|string  $tenant
     * @return void
     */
    public static function remove(Reference|string $tenant): void
    {
        $tenant = self::reference($tenant);
        $parent = self::parentOf($tenant);
        $nodes  = self::database()->table(self::TABLE);

        $nodes->clone()->where(['parent_type' => $tenant->type, 'parent_id' => $tenant->id])->update(['parent_type' => $parent?->type, 'parent_id' => $parent?->id]);
        $nodes->clone()->where(['tenant_type' => $tenant->type, 'tenant_id' => $tenant->id])->delete();
    }

    /**
     * The tenant's ancestors, nearest first, the tenant left out.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference>
     */
    #[\Override]
    public function ancestors(Reference $tenant): array
    {
        $ancestors = [];
        $current   = self::parentOf($tenant);

        while ($current !== null) {
            $ancestors[] = $current;
            $current     = self::parentOf($current);
        }

        return $ancestors;
    }

    /**
     * Whether the tenant is the ancestor or below it.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $ancestor
     * @return bool
     */
    #[\Override]
    public function isWithin(Reference $tenant, Reference $ancestor): bool
    {
        $matches = static fn (Reference $node): bool => $node->type === $ancestor->type && $node->id === $ancestor->id;

        return array_filter([$tenant, ...$this->ancestors($tenant)], $matches) !== [];
    }

    /**
     * The tenant and its descendants, on authorization's connection.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return \Illuminate\Contracts\Database\Query\Builder
     */
    #[\Override]
    public function subtree(Reference $tenant): Builder
    {
        $database = AuthorizationConnection::connection();
        $union    = $database->query()->selectRaw('? as tenant_type, ? as tenant_id', [$tenant->type, $tenant->id]);
        $frontier = [$tenant];

        while ($frontier !== []) {

            $below = [];

            foreach ($frontier as $node) {
                foreach (self::childrenOf($node) as $child) {
                    $union->unionAll($database->query()->selectRaw('? as tenant_type, ? as tenant_id', [$child->type, $child->id]));

                    $below[] = $child;
                }
            }

            $frontier = $below;
        }

        return $database->query()->fromSub($union, 'subtree')->select(['tenant_type', 'tenant_id']);
    }

    /**
     * The tenant's parent, or `null` for a root or a tenant not held.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return ?\SineMacula\Laravel\Authorization\Support\Reference
     */
    private static function parentOf(Reference $tenant): ?Reference
    {
        $row = self::database()->table(self::TABLE)->useWritePdo()->where(['tenant_type' => $tenant->type, 'tenant_id' => $tenant->id])->first();

        return is_string($row?->parent_type) && is_string($row->parent_id) ? new Reference($row->parent_type, $row->parent_id) : null;
    }

    /**
     * The tenant's children.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference>
     */
    private static function childrenOf(Reference $tenant): array
    {
        $rows = self::database()->table(self::TABLE)->useWritePdo()->where(['parent_type' => $tenant->type, 'parent_id' => $tenant->id])->orderBy('tenant_id')->get();

        return array_values($rows->map(static fn (object $row): Reference => new Reference((string) ($row->tenant_type), (string) ($row->tenant_id)))->all());
    }

    /**
     * The tenant given, or a `ClaimedTenant` of the id given.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|string  $tenant
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     */
    private static function reference(Reference|string $tenant): Reference
    {
        return is_string($tenant) ? new Reference(ClaimedTenant::TYPE, $tenant) : $tenant;
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
