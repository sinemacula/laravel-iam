<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Provisioning;

use SineMacula\Laravel\Sso\Provisioning\ProvisioningResult;

/**
 * Rolls back the provisioning transaction when SSO's helper refuses the link;
 * the listener catches it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RefusedLink extends \RuntimeException
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Provisioning\ProvisioningResult  $refusal
     */
    public function __construct(

        /** What the helper answered. */
        public readonly ProvisioningResult $refusal,
    ) {
        parent::__construct(sprintf('SSO\'s provisioning helper refused the link: [%s].', $refusal->status->value));
    }
}
