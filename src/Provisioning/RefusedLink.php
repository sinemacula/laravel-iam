<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Provisioning;

use SineMacula\Laravel\Sso\Provisioning\ProvisioningResult;

/**
 * SSO's provisioning helper refused to link the new identity: thrown inside the
 * listener's transaction, so the identity and its membership roll back with the
 * link the helper never wrote, and caught by the listener itself once the
 * transaction has rolled back, never propagated (IAM-7.1).
 *
 * It names the refusal's status alone, never the result, the subject or the
 * identity.
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
