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
 * the gateway throws is the delivery's failure and the code is not kept; MFA
 * never retries it. `laravel-authentication` delivers its codes, a code MFA
 * sends through it included, from its own queued job once the code has
 * committed, never inside the transaction that issued it, so an exception fails
 * that job and the code stays issued: retrying it is the application's queue's,
 * under the queue's retry policy, and the job checks that the code is still
 * current before it delivers again. This package never queues or retries a
 * delivery itself.
 *
 * A return means the message was accepted for delivery, by the gateway or the
 * SMS provider it hands the message to, not that it was received: neither
 * member retries a message lost after it was accepted, so the person asks for
 * another code. Deliver the message once; never log the code, the number or the
 * recipient. A gateway that queues its delivery itself must reveal what it
 * needs into a job whose whole payload is encrypted (one that implements
 * `ShouldBeEncrypted`), since the message refuses to be serialised, and MFA
 * then reports the code sent once it is queued, before it is delivered.
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
