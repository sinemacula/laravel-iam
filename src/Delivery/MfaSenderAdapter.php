<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Delivery;

use SineMacula\Laravel\Iam\Delivery\Enums\Channel;
use SineMacula\Laravel\Mfa\Codes\CodeMessage as MfaCodeMessage;

/**
 * One of MFA's senders, delivering through the application's gateway of its
 * channel (IAM-3.13): MFA's code message is translated into this package's
 * `CodeMessage` on that channel, its code revealed into a `Secret` of the
 * message's own and its factor's summary kept, and handed to the gateway.
 *
 * MFA calls it synchronously, inside the identity's transaction, once the code
 * is drawn, so a gateway that throws, or one that is neither bound nor named (a
 * `DeliveryNotConfiguredException`), rolls the code back: MFA scrubs the
 * failure of the code and the destination and rethrows it as its
 * `CodeDeliveryFailedException`, and retries nothing. A return means the
 * gateway accepted the message for delivery, not that it was received, and MFA
 * reports the code sent. It takes no lock and issues no statement. Each sender
 * is bound only while its channel's gateway is named or bound, and holds
 * nothing between calls (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
abstract readonly class MfaSenderAdapter
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Delivery\DeliverySettings  $settings
     */
    public function __construct(

        /** Resolves the gateway of the sender's channel. */
        private DeliverySettings $settings,
    ) {}

    /**
     * Send the message's code to its destination through the gateway of the
     * sender's channel.
     *
     * @param  \SineMacula\Laravel\Mfa\Codes\CodeMessage  $message
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\DeliveryNotConfiguredException
     */
    public function send(#[\SensitiveParameter] MfaCodeMessage $message): void
    {
        $channel = $this->channel();

        $this->settings->gateway($channel)->send(CodeMessage::fromMfa($message, $channel));
    }

    /**
     * The channel the sender delivers on.
     *
     * @return \SineMacula\Laravel\Iam\Delivery\Enums\Channel
     */
    abstract protected function channel(): Channel;
}
