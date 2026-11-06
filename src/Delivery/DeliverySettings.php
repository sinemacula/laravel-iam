<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Delivery;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose;
use SineMacula\Laravel\Iam\Contracts\EmailGateway;
use SineMacula\Laravel\Iam\Contracts\SmsGateway;
use SineMacula\Laravel\Iam\Delivery\Enums\Channel;
use SineMacula\Laravel\Iam\Exceptions\DeliveryNotConfiguredException;

/**
 * Resolves the application's gateways and the channel each code goes out on
 * (IAM-3.13), read on every call, so a change to the configuration or the
 * container reaches the next code.
 *
 * A channel's gateway is the application's binding of its contract, when there
 * is one (IAM-8.4), and otherwise the class `iam.delivery.{channel}` names,
 * which must implement the contract; anything else fails closed, blaming the
 * key for a class it names that is no gateway and the container's binding for
 * one that resolves to what is no gateway of the channel. A code of
 * `laravel-authentication`'s goes out on the channel `iam.delivery.types` maps
 * its identifier type to, read with the shipped routes when the application's
 * delivery configuration holds none, except a further factor's or an
 * enrolment's code, whose type is its factor's own channel. A type that maps to
 * no channel fails closed too.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class DeliverySettings
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** The container the application's gateway is bound or built in. */
        private Container $container,

        /** The configuration naming the gateways and the routes. */
        private Repository $config,
    ) {}

    /**
     * The gateway the channel's codes are delivered through.
     *
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Channel  $channel
     * @return \SineMacula\Laravel\Iam\Contracts\EmailGateway|\SineMacula\Laravel\Iam\Contracts\SmsGateway
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\DeliveryNotConfiguredException
     */
    public function gateway(Channel $channel): EmailGateway|SmsGateway
    {
        $contract = DeliverySeams::contract($channel);
        $key      = DeliverySeams::GATEWAYS . $channel->value;

        if ($this->container->bound($contract)) {
            return $this->resolved($channel, $contract, $contract);
        }

        if (!DeliverySeams::isNamed($this->config, $channel)) {
            throw DeliveryNotConfiguredException::forChannel($channel, $contract, $key);
        }

        $named = $this->config->get($key);

        assert(is_string($named));

        if (!is_subclass_of($named, $contract)) {
            throw DeliveryNotConfiguredException::forGateway($channel, $contract, $key, $named);
        }

        return $this->resolved($channel, $contract, $named);
    }

    /**
     * The channel a code of `laravel-authentication`'s goes out on: a further
     * factor's or an enrolment's on its factor's own channel, which is its
     * type, and any other on the channel `iam.delivery.types` maps its
     * identifier type to.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose  $purpose
     * @param  string  $type
     * @return \SineMacula\Laravel\Iam\Delivery\Enums\Channel
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\DeliveryNotConfiguredException
     */
    public function channelFor(CodePurpose $purpose, string $type): Channel
    {
        $route = match ($purpose) {
            CodePurpose::MFA, CodePurpose::ENROLLMENT => $type,
            default                                   => $this->route($type),
        };

        return (is_string($route) ? Channel::tryFrom($route) : null)
            ?? throw DeliveryNotConfiguredException::forType($type, DeliverySeams::TYPES);
    }

    /**
     * The gateway `iam.delivery.types` maps the identifier type to, as
     * configured, or `null` when it maps it to none.
     *
     * @param  string  $type
     * @return mixed
     */
    private function route(string $type): mixed
    {
        $types = $this->config->get(DeliverySeams::TYPES) ?? DeliverySeams::DEFAULT_TYPES;

        return is_array($types) ? $types[$type] ?? null : null;
    }

    /**
     * Build the gateway the container resolves by the abstract given, which
     * must implement the channel's contract: a binding, of the contract or of
     * the class named for it, that resolves to the other channel's gateway or
     * to no gateway fails closed, naming that binding.
     *
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Channel  $channel
     * @param  class-string  $contract
     * @param  string  $abstract
     * @return \SineMacula\Laravel\Iam\Contracts\EmailGateway|\SineMacula\Laravel\Iam\Contracts\SmsGateway
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\DeliveryNotConfiguredException
     */
    private function resolved(Channel $channel, string $contract, string $abstract): EmailGateway|SmsGateway
    {
        $gateway = $this->container->make($abstract);

        if ($channel === Channel::EMAIL && $gateway instanceof EmailGateway || $channel === Channel::SMS && $gateway instanceof SmsGateway) {
            return $gateway;
        }

        throw DeliveryNotConfiguredException::forBinding($channel, $contract, $abstract, get_debug_type($gateway));
    }
}
