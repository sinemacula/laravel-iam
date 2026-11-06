<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Contracts;

use SineMacula\Laravel\Iam\Delivery\CodeMessage;

/**
 * SMS gateway contract: the one way every member's codes reach a phone number
 * (IAM-3.13).
 *
 * The application implements it once, through its own SMS provider, and names
 * it in `iam.delivery.sms` (or binds it before this package registers). The
 * package then points `laravel-authentication`'s one-time code sender and MFA's
 * SMS sender at it, so a code from either member arrives as the same
 * `Delivery\CodeMessage`, to an E.164 number. The application writes every
 * message's wording itself, by the message's purpose; the package composes no
 * text.
 *
 * Where it runs depends on the member that issued the code. A code MFA sends
 * itself is delivered synchronously, inside MFA's transaction, so an exception
 * the gateway throws is the delivery's failure and the code is not kept.
 * `laravel-authentication` delivers its codes, a code MFA sends through it
 * included, from its own queued job once the code has committed, so an
 * exception fails that job, which the queue retries under its policy after
 * checking that the code is still current; the code stays issued. This package
 * never queues a delivery itself.
 *
 * A return means the provider accepted the message. Deliver the message once;
 * never log the code, the number or the recipient. A gateway that queues its
 * delivery itself must reveal what it needs into a job whose whole payload is
 * encrypted (one that implements `ShouldBeEncrypted`), since the message
 * refuses to be serialised, and MFA then reports the code sent once it is
 * queued, before it is delivered.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface SmsGateway
{
    /**
     * Send the message's code to its phone number.
     *
     * @param  \SineMacula\Laravel\Iam\Delivery\CodeMessage  $message
     * @return void
     */
    public function send(#[\SensitiveParameter] CodeMessage $message): void;
}
