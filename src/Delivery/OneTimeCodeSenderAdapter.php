<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Delivery;

use SineMacula\Laravel\Authentication\Codes\OneTimeCodeMessage;
use SineMacula\Laravel\Authentication\Contracts\OneTimeCodeSender;

/**
 * `laravel-authentication`'s one-time code sender, delivering through the
 * application's gateways (IAM-3.13).
 *
 * Each message is translated into this package's `CodeMessage` and handed to
 * the gateway its identifier type routes to through `iam.delivery.types`; a
 * code MFA sends through `laravel-authentication` (purpose `mfa` or
 * `enrollment`), whose type is its factor's channel, goes through that
 * channel's gateway. A type that routes to no gateway, and a gateway that is
 * neither bound nor named, throw a `DeliveryNotConfiguredException`. The
 * message names no factor: `laravel-authentication` does not say which factor a
 * code of MFA's is for, nor whether it is a sign-in's or a step-up's.
 *
 * `laravel-authentication` calls it from its own queued delivery job, once the
 * code has committed, so a gateway that throws fails the job and never rolls
 * the code back: retrying it is the application's queue's, under the queue's
 * retry policy, and the job checks first that the code is still current. A
 * return means the gateway accepted the message for delivery, not that it was
 * received. It holds nothing between calls (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class OneTimeCodeSenderAdapter implements OneTimeCodeSender
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Delivery\DeliverySettings  $settings
     */
    public function __construct(

        /** Routes the code to its channel and resolves the channel's gateway. */
        private DeliverySettings $settings,
    ) {}

    /**
     * Deliver the message's code through the gateway its type routes to.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\OneTimeCodeMessage  $message
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\DeliveryNotConfiguredException
     */
    #[\Override]
    public function send(#[\SensitiveParameter] OneTimeCodeMessage $message): void
    {
        $channel = $this->settings->channelFor($message->purpose, $message->type);

        $this->settings->gateway($channel)->send(CodeMessage::fromAuthentication($message, $channel));
    }
}
