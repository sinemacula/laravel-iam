<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Bindings\Contracts;

use Illuminate\Contracts\Config\Repository;

/**
 * Declares the member seams one capability binds its adapters over.
 *
 * Each capability's `*Seams` class implements it; the binding rule collects
 * every implementation's bindings once, as the service provider registers,
 * under the configuration every member will hold once registered (the
 * application's, with each member's packaged configuration beneath it).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
interface ProvidesSeams
{
    /**
     * Return the capability's seam bindings under the given configuration.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return list<\SineMacula\Laravel\Iam\Bindings\SeamBinding>
     */
    public function seams(Repository $config): array;
}
