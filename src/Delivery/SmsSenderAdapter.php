<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Delivery;

use SineMacula\Laravel\Iam\Delivery\Enums\Channel;
use SineMacula\Laravel\Mfa\Contracts\SmsSender;

/**
 * MFA's SMS sender, delivering through the application's SMS gateway
 * (IAM-3.13), as `MfaSenderAdapter` describes. It is bound only while the SMS
 * gateway is named or bound.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SmsSenderAdapter extends MfaSenderAdapter implements SmsSender
{
    /**
     * The SMS channel.
     *
     * @return \SineMacula\Laravel\Iam\Delivery\Enums\Channel
     */
    #[\Override]
    protected function channel(): Channel
    {
        return Channel::SMS;
    }
}
