<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Exceptions;

use SineMacula\Laravel\Iam\Delivery\Enums\Channel;

/**
 * Thrown when a code cannot be handed to a gateway (IAM-3.13): the channel's
 * gateway is neither bound nor named, the class named for it is no gateway of
 * that channel, the container binding it is resolved by resolves to what is no
 * gateway of that channel, or the code's type routes to no channel.
 *
 * It is thrown where the member delivers the code. MFA delivers inside the
 * identity's transaction, so the code it drew rolls back;
 * `laravel-authentication` delivers from its queued job once the code has
 * committed, so the job fails and the queue's retry policy applies. Either way
 * no code is dropped silently. The message names the configuration key, the
 * channel or the type, never the code, the destination or the recipient.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final class DeliveryNotConfiguredException extends \RuntimeException
{
    /**
     * Constructor.
     *
     * @param  string  $message
     * @param  ?\SineMacula\Laravel\Iam\Delivery\Enums\Channel  $channel
     * @param  ?string  $type
     */
    public function __construct(

        // What is missing, naming the key to set.
        string $message,

        /** The channel whose gateway could not be resolved; `null` when the type routes to none. */
        public readonly ?Channel $channel = null,

        /** The member's type of the destination that routes to no channel; `null` when a gateway is missing. */
        public readonly ?string $type = null,
    ) {
        parent::__construct($message);
    }

    /**
     * Build an exception for a channel whose gateway the application has
     * neither bound nor named.
     *
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Channel  $channel
     * @param  class-string  $contract
     * @param  string  $key
     * @return self
     */
    public static function forChannel(Channel $channel, string $contract, string $key): self
    {
        $message = 'No %s gateway is bound as %s or named in %s, so the code cannot be delivered:'
            . ' name the application\'s gateway there, or bind it before this package registers.';

        return new self(sprintf($message, $channel->value, $contract, $key), $channel);
    }

    /**
     * Build an exception for a gateway named by something that is not a class
     * implementing the channel's contract.
     *
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Channel  $channel
     * @param  class-string  $contract
     * @param  string  $key
     * @param  string  $named
     * @return self
     */
    public static function forGateway(Channel $channel, string $contract, string $key, string $named): self
    {
        $message = '%s names [%s], which is not a class implementing %s, so the code cannot be delivered.';

        return new self(sprintf($message, $key, $named, $contract), $channel);
    }

    /**
     * Build an exception for a container binding, of the channel's contract or
     * of the class named for it, that resolves to what is no gateway of the
     * channel: the binding is at fault, not the configuration key.
     *
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Channel  $channel
     * @param  class-string  $contract
     * @param  string  $abstract
     * @param  string  $resolved
     * @return self
     */
    public static function forBinding(Channel $channel, string $contract, string $abstract, string $resolved): self
    {
        $message = 'The container binding of %s resolves to [%s], which is no gateway of the %s channel,'
            . ' so the code cannot be delivered: bind it to a class implementing %s.';

        return new self(sprintf($message, $abstract, $resolved, $channel->value, $contract), $channel);
    }

    /**
     * Build an exception for a type of destination that routes to no channel.
     *
     * @param  string  $type
     * @param  string  $key
     * @return self
     */
    public static function forType(string $type, string $key): self
    {
        $message = 'A code to a destination of type [%s] routes to no gateway, so it cannot be delivered:'
            . ' %s maps each of laravel-authentication\'s identifier types to `email` or `sms`,'
            . ' and a further factor\'s code goes out on its own channel, `email` or `sms`.';

        return new self(sprintf($message, $type, $key), type: $type);
    }
}
