<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Delivery;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodeMessage;
use SineMacula\Laravel\Authentication\Exceptions\SecretNotRevealedException;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Iam\Delivery\Enums\Channel;
use SineMacula\Laravel\Iam\Delivery\Enums\Purpose;
use SineMacula\Laravel\Iam\Delivery\Enums\Source;
use SineMacula\Laravel\Mfa\Codes\CodeMessage as MfaCodeMessage;
use SineMacula\Laravel\Mfa\Enums\Purpose as MfaPurpose;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;

/**
 * A code to deliver, as the application's email and SMS gateways are given it
 * (IAM-3.13): the same neutral details whichever member issued the code, which
 * the application words and lays out itself.
 *
 * It carries the code, what it is for (this package's purpose, and the member's
 * own for detail), the channel and the destination in its normal form (a
 * trimmed, lower-cased address, an E.164 number), when the code stops working,
 * the recipient, the application (the guard of the same name, for
 * `laravel-authentication`'s codes) and, for a code MFA sent itself, its
 * factor's summary with the destination masked.
 *
 * The code is a `Secret`: reveal it only into the message to the recipient, and
 * never log it. The destination and the recipient are held as
 * `\SensitiveParameterValue`s and read through `destination()` and
 * `recipient()`. The message refuses to be serialised or unserialised, and its
 * code refuses to be cast to a string or encoded as JSON, so the message as a
 * whole cannot be encoded either; a dump of it shows neither the code, the
 * destination nor the recipient. So it is never queued or cached by accident: a
 * gateway that queues its delivery reveals what it needs into a job of its own,
 * and encrypts that job's whole payload. Logged by accident, it is logged as
 * MFA's log redaction logs an object, by its public properties, the code
 * redacted under its key, and neither the destination nor the recipient, which
 * are not public, appear; it is not `\JsonSerializable`, so the redaction never
 * asks it for a JSON form it would refuse and so fail the log. The factor's
 * summary masks its destination, but its label is the person's own text and is
 * shown as it is.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class CodeMessage
{
    /** @var string What a dump shows in place of the destination and the recipient. */
    public const string REDACTED = Secret::REDACTED;

    /** @var \SineMacula\Laravel\Iam\Delivery\Enums\Purpose What the code is for, in this package's own words. */
    public Purpose $purpose;

    /** @var \SineMacula\Laravel\Iam\Delivery\Enums\Source The member that issued the code. */
    public Source $source;

    /** @var \SensitiveParameterValue<string> The destination, hidden from dumps. */
    private \SensitiveParameterValue $destination;

    /** @var \SensitiveParameterValue<\Illuminate\Contracts\Auth\Authenticatable> The recipient, hidden from dumps. */
    private \SensitiveParameterValue $recipient;

    /**
     * Constructor.
     *
     * @param  string  $application
     * @param  \SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose|\SineMacula\Laravel\Mfa\Enums\Purpose  $memberPurpose
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Channel  $channel
     * @param  string  $type
     * @param  string  $destination
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret  $code
     * @param  \Carbon\CarbonImmutable  $expiresAt
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $recipient
     * @param  ?\SineMacula\Laravel\Mfa\Factors\FactorSummary  $factor
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The application the code is for; for `laravel-authentication`'s codes, the guard of the same name. */
        public string $application,

        /** What the code is for, as the member that issued it says. */
        public CodePurpose|MfaPurpose $memberPurpose,

        /** The channel the code goes out on, and so the gateway that delivers it. */
        public Channel $channel,

        /** The member's type of the destination: `laravel-authentication`'s identifier type (`email`, `phone`) or the factor's type (`sms`, `email`). */
        public string $type,

        // The destination, in its normal form.
        #[\SensitiveParameter]
        string $destination,

        /** The code. */
        public Secret $code,

        /** When the code stops working. */
        public CarbonImmutable $expiresAt,

        // The identity the code is for.
        #[\SensitiveParameter]
        Authenticatable $recipient,

        /** The factor the code is sent for, its destination masked; `null` when the member does not name one. */
        public ?FactorSummary $factor = null,
    ) {
        if (trim($application) === '') {
            throw new \InvalidArgumentException('A code message must name the application the code is for.');
        }

        if (trim($type) === '') {
            throw new \InvalidArgumentException('A code message must name the type of its destination.');
        }

        if (trim($destination) === '') {
            throw new \InvalidArgumentException('A code message must name its destination.');
        }

        $this->purpose     = $memberPurpose instanceof CodePurpose ? Purpose::fromAuthentication($memberPurpose) : Purpose::fromMfa($memberPurpose);
        $this->source      = $memberPurpose instanceof CodePurpose ? Source::AUTHENTICATION : Source::MFA;
        $this->destination = new \SensitiveParameterValue($destination);
        $this->recipient   = new \SensitiveParameterValue($recipient);
    }

    /**
     * What a dump shows: everything but the code, the destination and the
     * recipient, which show the placeholder.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return [
            'application'   => $this->application,
            'purpose'       => $this->purpose,
            'memberPurpose' => $this->memberPurpose,
            'source'        => $this->source,
            'channel'       => $this->channel,
            'type'          => $this->type,
            'destination'   => self::REDACTED,
            'code'          => self::REDACTED,
            'expiresAt'     => $this->expiresAt,
            'recipient'     => self::REDACTED,
            'factor'        => $this->factor,
        ];
    }

    /**
     * Refuse to be serialised.
     *
     * @return array<string, mixed>
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\SecretNotRevealedException
     */
    public function __serialize(): array // NOSONAR: a magic method PHP names
    {
        throw SecretNotRevealedException::for('serialised');
    }

    /**
     * Refuse to be unserialised.
     *
     * @param  array<array-key, mixed>  $data
     * @return void
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\SecretNotRevealedException
     */
    public function __unserialize(array $data): void // NOSONAR: a magic method PHP names, given the data it refuses
    {
        throw SecretNotRevealedException::for('unserialised');
    }

    /**
     * The message for a code `laravel-authentication` hands its one-time code
     * sender, on the channel given. It names no factor:
     * `laravel-authentication` does not say which factor a code of MFA's is
     * for.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\OneTimeCodeMessage  $message
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Channel  $channel
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function fromAuthentication(#[\SensitiveParameter] OneTimeCodeMessage $message, Channel $channel): self
    {
        return new self(
            $message->guard,
            $message->purpose,
            $channel,
            $message->type,
            $message->identifier,
            $message->code,
            $message->expiresAt,
            $message->identity,
        );
    }

    /**
     * The message for a code MFA hands its SMS or email sender, on the channel
     * given. MFA's code is revealed into a `Secret` of the message's own.
     *
     * @param  \SineMacula\Laravel\Mfa\Codes\CodeMessage  $message
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Channel  $channel
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function fromMfa(#[\SensitiveParameter] MfaCodeMessage $message, Channel $channel): self
    {
        return new self(
            $message->application,
            $message->purpose,
            $channel,
            $message->type,
            $message->destination(),
            new Secret($message->code->reveal()),
            $message->expiresAt,
            $message->recipient(),
            $message->factor,
        );
    }

    /**
     * The destination, in its normal form: an email address for the email
     * channel, an E.164 number for SMS.
     *
     * @return string
     */
    public function destination(): string
    {
        return $this->destination->getValue();
    }

    /**
     * The identity the code is for.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable
     */
    public function recipient(): Authenticatable
    {
        return $this->recipient->getValue();
    }
}
