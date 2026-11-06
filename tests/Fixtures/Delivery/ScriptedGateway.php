<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Delivery;

use SineMacula\Laravel\Iam\Contracts\EmailGateway;
use SineMacula\Laravel\Iam\Contracts\SmsGateway;
use SineMacula\Laravel\Iam\Delivery\CodeMessage;

/**
 * A gateway of either channel that does what its test scripts: the script is
 * given each message and the gateway, and records a delivery with `deliver()`,
 * reads whether the provider was told to fail with `$failing`, or does whatever
 * else the test needs it to, well or badly, so a test can prove the gateway
 * kits catch what they promise to, or watch the member's transaction while a
 * code is delivered.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ScriptedGateway implements EmailGateway, SmsGateway
{
    /** @var bool Whether the provider was told to fail the next delivery. */
    public bool $failing = false;

    /** @var array<string, int> How many messages were delivered to each destination. */
    private array $delivered = [];

    /**
     * Constructor.
     *
     * @param  \Closure(\SineMacula\Laravel\Iam\Delivery\CodeMessage, self): void  $script
     */
    public function __construct(

        /** What the gateway does with each message. */
        private readonly \Closure $script,
    ) {}

    /**
     * A gateway that delivers each message once, and throws, delivering
     * nothing, when the provider was told to fail.
     *
     * @return self
     */
    public static function wellBehaved(): self
    {
        return new self(static function (CodeMessage $message, self $gateway): void {
            if ($gateway->failing) {
                throw new \RuntimeException('The provider refused the message.');
            }

            $gateway->deliver($message);
        });
    }

    /**
     * Do what the script says with the message.
     *
     * @param  \SineMacula\Laravel\Iam\Delivery\CodeMessage  $message
     * @return void
     */
    #[\Override]
    public function send(#[\SensitiveParameter] CodeMessage $message): void
    {
        ($this->script)($message, $this);
    }

    /**
     * Record a delivery of the message to its destination.
     *
     * @param  \SineMacula\Laravel\Iam\Delivery\CodeMessage  $message
     * @return void
     */
    public function deliver(#[\SensitiveParameter] CodeMessage $message): void
    {
        $this->delivered[$message->destination()] = $this->deliveredTo($message->destination()) + 1;
    }

    /**
     * How many messages were delivered to the destination.
     *
     * @param  string  $destination
     * @return int
     */
    public function deliveredTo(#[\SensitiveParameter] string $destination): int
    {
        return $this->delivered[$destination] ?? 0;
    }
}
