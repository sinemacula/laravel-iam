<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Delivery;

use SineMacula\Laravel\Iam\Delivery\Enums\Channel;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;

/**
 * MFA's email sender, delivering through the application's email gateway
 * (IAM-3.13), as `MfaSenderAdapter` describes. It is bound only while the email
 * gateway is named or bound.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class EmailSenderAdapter extends MfaSenderAdapter implements EmailSender
{
    /**
     * The email channel.
     *
     * @return \SineMacula\Laravel\Iam\Delivery\Enums\Channel
     */
    #[\Override]
    protected function channel(): Channel
    {
        return Channel::EMAIL;
    }
}
