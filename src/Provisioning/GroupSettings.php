<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Provisioning;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Iam\Bindings\ConfiguredImplementations;
use SineMacula\Laravel\Iam\Contracts\GroupMapping;
use SineMacula\Laravel\Iam\Contracts\GroupResync;
use SineMacula\Laravel\Iam\Exceptions\GroupMappingMisconfiguredException;

/**
 * The application's mapping of provider groups to grants, and its opt-in
 * re-sync of them at later sign-ins (IAM-7.2), when it has either.
 *
 * The mapping is the application's binding of `Contracts\GroupMapping`, when
 * there is one (IAM-8.4), else the class `iam.provisioning.groups.mapping`
 * names, else, while `iam.provisioning.groups.map` maps any group, the mapping
 * read from that map (`ConfiguredGroupMapping`); with none of them, groups map
 * to nothing and provisioning grants nothing. The re-sync is the application's
 * binding of `Contracts\GroupResync`, else the class
 * `iam.provisioning.groups.resync` names (`MappedGroupResync`, say); with
 * neither, nothing is re-synced. Each is resolved from the container each time
 * it is asked for, so whatever the application binds, whenever it binds it, is
 * the one asked, and nothing is kept between calls (IAM-8.1). A class named
 * that implements no such contract, a value that is no class name at all, or a
 * binding that resolves to no implementation, throws
 * `GroupMappingMisconfiguredException` rather than map nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class GroupSettings
{
    /** @var string The configuration key naming the application's group mapping. */
    public const string MAPPING = 'iam.provisioning.groups.mapping';

    /** @var string The configuration key mapping each group to its roles, read while no mapping is named or bound. */
    public const string MAP = 'iam.provisioning.groups.map';

    /** @var string The configuration key naming the application's group re-sync. */
    public const string RESYNC = 'iam.provisioning.groups.resync';

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
     * The application's group mapping, as bound, as named or as mapped, or
     * `null` when groups map to nothing.
     *
     * @return ?\SineMacula\Laravel\Iam\Contracts\GroupMapping
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\GroupMappingMisconfiguredException
     */
    public function mapping(): ?GroupMapping
    {
        $mapping = ConfiguredImplementations::find($this->container, $this->config, GroupMapping::class, self::MAPPING, GroupMappingMisconfiguredException::class);

        if ($mapping !== null) {
            return $mapping;
        }

        $map = $this->config->get(self::MAP);

        return $map === null || $map === [] ? null : new ConfiguredGroupMapping($this->config);
    }

    /**
     * The application's group re-sync, as bound or as named, or `null` when
     * nothing is re-synced.
     *
     * @return ?\SineMacula\Laravel\Iam\Contracts\GroupResync
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\GroupMappingMisconfiguredException
     */
    public function resync(): ?GroupResync
    {
        return ConfiguredImplementations::find($this->container, $this->config, GroupResync::class, self::RESYNC, GroupMappingMisconfiguredException::class);
    }
}
