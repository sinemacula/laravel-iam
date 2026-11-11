<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Builder as EloquentBuilder;
use Illuminate\Database\Query\Builder as QueryBuilder;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Resolvers\FlatTenantTree;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\TenantChain;
use SineMacula\Laravel\Iam\Bindings\ConfiguredImplementations;
use SineMacula\Laravel\Iam\Contracts\Memberships;
use SineMacula\Laravel\Iam\Exceptions\TenancyMisconfiguredException;

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
    /** @var string The configuration key naming the application's memberships. */
    public const string MEMBERSHIPS = 'iam.tenancy.memberships';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** The container the application's implementations are bound or built in. */
        private Container $container,

        /** The configuration naming them. */
        private Repository $config,
    ) {}

    /**
     * The application's memberships, which an adapter answering from them is
     * never asked without.
     *
     * @return \SineMacula\Laravel\Iam\Contracts\Memberships
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\TenancyMisconfiguredException
     */
    public function memberships(): Memberships
    {
        return ConfiguredImplementations::find($this->container, $this->config, Memberships::class, self::MEMBERSHIPS, TenancyMisconfiguredException::class)
            ?? throw TenancyMisconfiguredException::forNone(self::MEMBERSHIPS, Memberships::class);
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
     * Whether the application has memberships: bound in the container, or
     * named.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return bool
     */
    public static function hasMemberships(Container $container, Repository $config): bool
    {
        return ConfiguredImplementations::isConfigured($container, $config, Memberships::class, self::MEMBERSHIPS);
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
