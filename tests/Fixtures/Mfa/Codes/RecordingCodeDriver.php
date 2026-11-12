<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Mfa\Codes;

use SineMacula\Laravel\Mfa\Codes\CodeMessage;
use SineMacula\Laravel\Mfa\Drivers\AbstractCodeDriver;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;

/**
 * An application's own code driver that keeps every message it delivers.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordingCodeDriver extends AbstractCodeDriver
{
    /** @var list<\SineMacula\Laravel\Mfa\Codes\CodeMessage> Every message the driver was handed, in order. */
    private array $messages = [];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\ChannelKind  $kind
     * @param  ?\Closure(): void  $observer
     */
    public function __construct(

        /** The channel kind the driver states. */
        private readonly ChannelKind $kind,

        /** Called as each message is delivered. */
        private readonly ?\Closure $observer = null,
    ) {}

    /**
     * The channel kind the driver was given.
     *
     * @return \SineMacula\Laravel\Mfa\Enums\ChannelKind
     */
    #[\Override]
    public function channelKind(): ChannelKind
    {
        return $this->kind;
    }

    /**
     * The destination trimmed, or `null` when it is blank.
     *
     * @param  string  $destination
     * @return ?string
     */
    #[\Override]
    public function normalizeDestination(#[\SensitiveParameter] string $destination): ?string
    {
        $trimmed = trim($destination);

        return $trimmed === '' ? null : $trimmed;
    }

    /**
     * Every message the driver was handed, in order.
     *
     * @return list<\SineMacula\Laravel\Mfa\Codes\CodeMessage>
     */
    public function messages(): array
    {
        return $this->messages;
    }

    /**
     * Keep the message once the observer has watched it go.
     *
     * @param  \SineMacula\Laravel\Mfa\Codes\CodeMessage  $message
     * @return void
     */
    #[\Override]
    protected function send(#[\SensitiveParameter] CodeMessage $message): void
    {
        if ($this->observer !== null) {
            ($this->observer)();
        }

        $this->messages[] = $message;
    }
}
