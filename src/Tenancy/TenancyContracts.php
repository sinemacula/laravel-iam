<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Iam\Bindings\ConfiguredImplementations;
use SineMacula\Laravel\Iam\Contracts\Memberships;
use SineMacula\Laravel\Iam\Contracts\TenantTree;
use SineMacula\Laravel\Iam\Exceptions\TenancyMisconfiguredException;

/**
 * Finds the application's memberships (IAM-7.4) and its tenant tree (IAM-7.5).
 *
 * Each is the application's binding of its contract, when there is one
 * (IAM-8.4), and otherwise the class its key names
 * (`iam.tenancy.memberships`, `iam.tenancy.tree`), which must implement it;
 * either is resolved from the container on every call, so whatever the
 * application binds, whenever it binds it, is the one asked, and nothing is
 * kept between calls (IAM-8.1). Naming none (`null`, or blank text) is the
 * application's choice: SSO's tenant membership, link eligibility and principal
 * scope then keep SSO's defaults, which refuse, and without a tree every tenant
 * stands alone. A class named that is no implementation, a value that is no
 * class name at all (`true`, `false`, a number, an array), or a binding that
 * resolves to no implementation, fails closed rather than answer as though
 * there were none. Whatever the implementation throws propagates.
 *
 * Whether either is configured is also read by the binding rule
 * (`TenancySeams`), as this package registers and once more once every
 * provider has registered, from the configuration and the container as they
 * stand then; a binding made later, from a provider's `boot()`, still answers
 * here.
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

    /** @var string The configuration key naming the application's tenant tree. */
    public const string TREE = 'iam.tenancy.tree';

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
     * The application's tenant tree, or `null` when it has none and every
     * tenant stands alone.
     *
     * @return ?\SineMacula\Laravel\Iam\Contracts\TenantTree
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\TenancyMisconfiguredException
     */
    public function tree(): ?TenantTree
    {
        return ConfiguredImplementations::find($this->container, $this->config, TenantTree::class, self::TREE, TenancyMisconfiguredException::class);
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
     * Whether the application has a tenant tree: bound in the container, or
     * named.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return bool
     */
    public static function hasTree(Container $container, Repository $config): bool
    {
        return ConfiguredImplementations::isConfigured($container, $config, TenantTree::class, self::TREE);
    }
}
