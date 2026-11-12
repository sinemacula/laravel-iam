<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Builder as EloquentBuilder;
use Illuminate\Database\Query\Builder as QueryBuilder;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Resolvers\FlatTenantTree;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\TenantChain;
use SineMacula\Laravel\Iam\Contracts\Memberships;

/**
 * Finds the application's memberships (IAM-7.4) and its tenant tree (IAM-7.5)
 * on every call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TenancyContracts
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The container the application binds its memberships in. */
        private Container $container,
    ) {}

    /**
     * The application's memberships, which an adapter answering from them is
     * never asked without.
     *
     * @return \SineMacula\Laravel\Iam\Contracts\Memberships
     *
     * @throws \LogicException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function memberships(): Memberships
    {
        return $this->container->bound(Memberships::class)
            ? $this->container->make(Memberships::class)
            : throw new \LogicException(sprintf('%s is unbound; bind an implementation of your own to it.', Memberships::class));
    }

    /**
     * `laravel-authorization`'s tenant tree, or `null` while it is its flat
     * default.
     *
     * @return ?\SineMacula\Laravel\Authorization\Contracts\TenantTree
     */
    public function tree(): ?TenantTree
    {
        $tree = TenantChain::tree();

        return $tree instanceof FlatTenantTree ? null : $tree;
    }

    /**
     * The tenant and every tenant below it, as `laravel-authorization`'s tenant
     * tree's subtree selects them.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference>
     *
     * @throws \UnexpectedValueException
     */
    public function subtree(Reference $tenant): array
    {
        $subtree = TenantChain::tree()->subtree($tenant);
        $query   = $subtree instanceof EloquentBuilder ? $subtree->toBase() : $subtree;

        if (!$query instanceof QueryBuilder) {
            throw new \UnexpectedValueException(sprintf('The tenant tree answered a subtree of [%s], which is no query.', $subtree::class));
        }

        $tenants = [];

        foreach ($query->get() as $row) {
            $tenants[] = new Reference((string) $row->tenant_type, (string) $row->tenant_id);
        }

        return $tenants;
    }

    /**
     * Whether `laravel-authorization`'s tenant tree is the application's, not
     * its flat default.
     *
     * @return bool
     */
    public static function hasTree(): bool
    {
        return !TenantChain::tree() instanceof FlatTenantTree;
    }
}
