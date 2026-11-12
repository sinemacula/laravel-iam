<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Provisioning;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Iam\Contracts\GroupMapping;
use SineMacula\Laravel\Iam\Contracts\GroupResync;

/**
 * The application's group mapping and re-sync (IAM-7.2), resolved on every
 * call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class GroupSettings
{
    /** @var string The configuration key mapping each group to its roles, read while no mapping is bound. */
    public const string MAP = 'iam.provisioning.groups.map';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** The container the application binds its mapping and re-sync in. */
        private Container $container,

        /** The configuration holding the map. */
        private Repository $config,
    ) {}

    /**
     * The bound mapping, else the configured map's, or `null` when groups map
     * to nothing.
     *
     * @return ?\SineMacula\Laravel\Iam\Contracts\GroupMapping
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function mapping(): ?GroupMapping
    {
        if ($this->container->bound(GroupMapping::class)) {
            return $this->container->make(GroupMapping::class);
        }

        $map = $this->config->get(self::MAP);

        return $map === null || $map === [] ? null : new ConfiguredGroupMapping($this->config);
    }

    /**
     * The bound re-sync, or `null` when nothing is re-synced.
     *
     * @return ?\SineMacula\Laravel\Iam\Contracts\GroupResync
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function resync(): ?GroupResync
    {
        return $this->container->bound(GroupResync::class) ? $this->container->make(GroupResync::class) : null;
    }
}
