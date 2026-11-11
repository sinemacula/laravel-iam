<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodeMessage;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\OneTimeCodeSender;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Mfa\Codes\CodeMessage;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;
use SineMacula\Laravel\Mfa\Contracts\SmsSender;
use SineMacula\Laravel\Mfa\Enums\Purpose;

/**
 * MFA's SMS and email senders, forwarding each code to the application's
 * `laravel-authentication` one-time code sender (IAM-3.13).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CodeSenderAdapter implements EmailSender, SmsSender
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\OneTimeCodeSender  $sender
     */
    public function __construct(

        /** The application's sender. */
        private OneTimeCodeSender $sender,
    ) {}

    /**
     * Send the code as a `laravel-authentication` factor code.
     *
     * @param  \SineMacula\Laravel\Mfa\Codes\CodeMessage  $message
     * @return void
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    #[\Override]
    public function send(#[\SensitiveParameter] CodeMessage $message): void
    {
        $recipient = $message->recipient();

        if (!$recipient instanceof Identity) {
            throw UnresolvedReferenceException::forIdentity($recipient::class);
        }

        $this->sender->send(new OneTimeCodeMessage(
            $message->application,
            $message->purpose === Purpose::ENROLLMENT ? CodePurpose::ENROLLMENT : CodePurpose::MFA,
            $message->type,
            $message->destination(),
            new Secret($message->code->reveal()),
            $message->expiresAt,
            $recipient,
        ));
    }
}
