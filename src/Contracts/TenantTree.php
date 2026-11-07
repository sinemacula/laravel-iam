<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Contracts;

use Illuminate\Contracts\Database\Query\Builder;

/**
 * Tenant tree contract: the application's one tenant tree, shared by every
 * member that needs it (IAM-7.5).
 *
 * The tree is the application's own data, its tenants named by the opaque ids
 * SSO and `laravel-authentication` name them by, compared byte for byte. The
 * application implements this once, names it in `iam.tenancy.tree` (or binds it
 * in the container by the time every provider has registered, in an application
 * provider's `register()`, say: one bound from a `boot()` is asked, but leaves
 * SSO's own inheritance bound), and the package answers SSO's enforcement
 * inheritance from it (the nearest tenant, from the one asked up through its
 * ancestors, that has a rule, on or off) and revokes through it when an
 * enforcing tenant's rule changes or a tenant moves. Without one, every tenant
 * stands alone.
 *
 * The tree has no cycles: a tenant is never its own ancestor, nor an ancestor
 * of an ancestor of its own. `ancestors()` answers nearest first, the tenant
 * itself excluded, and nothing for a root or a tenant the tree does not hold;
 * `descendants()` answers every tenant below, the tenant itself excluded;
 * `isWithin()` agrees with both, the tenant counting as within itself; and
 * `subtree()` is a query of the tenant and every descendant, which a member can
 * join or nest, selecting their ids in the `tenant_id` column.
 *
 * It is asked inside SSO's admission, before and under SSO's locks, and inside
 * the transaction that changes an enforcing tenant's rule, so read the write
 * connection every time, cache nothing, keep nothing of one call for the next,
 * and take no lock. A tenant moved is reported once, inside the transaction
 * that moves it, after the write (`Iam::treeChanges()->changed($tenantId)`);
 * a removal is reported as the move of each child moved out from under the
 * removed tenant. A read that fails throws.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface TenantTree
{
    /** @var string The column `subtree()` selects each tenant's id in. */
    public const string ID_COLUMN = 'tenant_id';

    /**
     * The tenant's ancestors, nearest first, the tenant itself excluded:
     * nothing for a root, or for a tenant the tree does not hold.
     *
     * @param  string  $tenantId
     * @return list<string>
     *
     * @throws \Throwable
     */
    public function ancestors(string $tenantId): array;

    /**
     * Every tenant below the tenant, at any depth, the tenant itself excluded,
     * each once: a tenant answered twice is taken for a cycle and refused.
     *
     * @param  string  $tenantId
     * @return iterable<string>
     *
     * @throws \Throwable
     */
    public function descendants(string $tenantId): iterable;

    /**
     * Whether the tenant is the ancestor given, or below it.
     *
     * @param  string  $tenantId
     * @param  string  $ancestorId
     * @return bool
     *
     * @throws \Throwable
     */
    public function isWithin(string $tenantId, string $ancestorId): bool;

    /**
     * The tenant and every tenant below it, as a query selecting their ids in
     * the `tenant_id` column.
     *
     * @param  string  $tenantId
     * @return \Illuminate\Contracts\Database\Query\Builder
     *
     * @throws \Throwable
     */
    public function subtree(string $tenantId): Builder;
}
