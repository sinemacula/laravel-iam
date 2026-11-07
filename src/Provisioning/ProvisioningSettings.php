<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Provisioning;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Iam\Bindings\ConfiguredImplementations;
use SineMacula\Laravel\Iam\Contracts\Provisioner;
use SineMacula\Laravel\Iam\Exceptions\ProvisionerMisconfiguredException;

/**
 * Whether provisioning is on, and the application's provisioner when it is
 * (IAM-7.1).
 *
 * The provisioner is the application's binding of `Contracts\Provisioner`, when
 * there is one (IAM-8.4), and otherwise the class
 * `iam.provisioning.provisioner` names, which must implement it; either is
 * resolved from the container each time it is asked for, so whatever the
 * application binds, whenever it binds it (in a provider's `boot()`, or in a
 * test once the application has booted), is the one asked, and nothing is kept
 * between calls (IAM-8.1). With neither, provisioning is off: that is the
 * application's choice, made by naming none (`null`, or blank text), and an
 * unlinked result is then left to SSO's own answer, `unlinked`. A class named
 * that is no provisioner, a value that is no class name at all (`true`,
 * `false`, a number, an array), or a binding that resolves to no provisioner,
 * fails closed rather than turn provisioning off.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ProvisioningSettings
{
    /** @var string The configuration key naming the application's provisioner. */
    public const string KEY = 'iam.provisioning.provisioner';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** The container the application's provisioner is bound or built in. */
        private Container $container,

        /** The configuration naming the application's provisioner. */
        private Repository $config,
    ) {}

    /**
     * The application's provisioner, as bound or as named, or `null` when
     * provisioning is off.
     *
     * @return ?\SineMacula\Laravel\Iam\Contracts\Provisioner
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\ProvisionerMisconfiguredException
     */
    public function provisioner(): ?Provisioner
    {
        return ConfiguredImplementations::find($this->container, $this->config, Provisioner::class, self::KEY, ProvisionerMisconfiguredException::class);
    }
}
