<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Delivery;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Contracts\OneTimeCodeSender;
use SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Iam\Contracts\EmailGateway;
use SineMacula\Laravel\Iam\Contracts\SmsGateway;
use SineMacula\Laravel\Iam\Delivery\Enums\Channel;
use SineMacula\Laravel\Mfa\Codes\NullEmailSender;
use SineMacula\Laravel\Mfa\Codes\NullSmsSender;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;
use SineMacula\Laravel\Mfa\Contracts\SmsSender;

/**
 * The seams every member's codes are delivered through, pointed at the
 * application's own gateways (IAM-3.13): `laravel-authentication`'s one-time
 * code sender, and MFA's SMS and email senders.
 *
 * A gateway is available once the application names its class
 * (`iam.delivery.email`, `iam.delivery.sms`) or has bound its contract before
 * this package registers. MFA's sender of a channel is pointed at that
 * channel's gateway while it is available. `laravel-authentication`'s one-time
 * code sender is pointed at the gateways once every gateway
 * `iam.delivery.types` routes to is available, since binding it at all tells
 * `laravel-authentication` its codes can be delivered. A gateway the
 * application has neither named nor bound binds nothing (IAM-1.3): MFA keeps
 * its own senders, which refuse to send, and `laravel-authentication` its
 * unbound sender.
 *
 * MFA's challenge gateway is pointed at `laravel-authentication`'s factor codes
 * while that path can deliver them (`routesFactorCodes()`, which its binding in
 * `Mfa\MfaSeams` reads): `laravel-authentication`'s one-time code sender is
 * bound, the application's or this package's. The adapter then judges each code
 * as it is sent, against the container as it stands: only a factor of MFA's own
 * `sms` or `email` type, built by MFA's own driver over this package's sender
 * of its channel, takes `laravel-authentication`'s path; any other code, one
 * whose sender or driver the application bound or registered at any time
 * included, is delivered by MFA through that sender or driver. Either way the
 * senders MFA's boot check judges are the ones its codes go through: on
 * `laravel-authentication`'s path a factor's code goes out through the gateway
 * of its channel, which is available exactly while MFA's sender of that channel
 * is pointed at it.
 *
 * The switches read the configuration every member will hold once registered,
 * and the container as it stands when this package registers: a gateway the
 * application binds later, in its own provider's `register()` or `boot()`,
 * comes too late to point a sender at it, so the application names it instead.
 * A sender the application binds later replaces this package's adapter, as the
 * binding rule allows, and is the one MFA's codes of its channel go through.
 * Each adapter replaces the member's own default only (IAM-8.4), and is
 * transient (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class DeliverySeams implements ProvidesSeams
{
    /** @var string The key each gateway's class is named under, followed by its channel. */
    public const string GATEWAYS = 'iam.delivery.';

    /** @var string The key mapping each of `laravel-authentication`'s identifier types to a gateway. */
    public const string TYPES = 'iam.delivery.types';

    /** @var array<string, string> The routes read when the application's delivery configuration holds none. */
    public const array DEFAULT_TYPES = ['email' => 'email', 'phone' => 'sms'];

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The container a gateway or a one-time code sender may be bound in. */
        private Container $container,
    ) {}

    /**
     * Return the bindings of the members' senders, each on while the gateways
     * it delivers through are available.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return list<\SineMacula\Laravel\Iam\Bindings\SeamBinding>
     */
    #[\Override]
    public function seams(Repository $config): array
    {
        $routed = fn (Repository $switches): bool => $this->isRouted($switches);
        $sms    = fn (Repository $switches): bool => $this->isAvailable($switches, Channel::SMS);
        $email  = fn (Repository $switches): bool => $this->isAvailable($switches, Channel::EMAIL);

        return [
            new SeamBinding(OneTimeCodeSender::class, OneTimeCodeSenderAdapter::class, [], appliesWhen: $routed),
            new SeamBinding(SmsSender::class, SmsSenderAdapter::class, [NullSmsSender::class], appliesWhen: $sms),
            new SeamBinding(EmailSender::class, EmailSenderAdapter::class, [NullEmailSender::class], appliesWhen: $email),
        ];
    }

    /**
     * Whether `laravel-authentication`'s path can deliver MFA's factor codes,
     * so MFA's challenge gateway may be pointed at it:
     * `laravel-authentication`'s one-time code sender is bound, by the
     * application before this package registers or by this package once every
     * gateway the routes reach is available. One that binds neither leaves
     * MFA's own challenges, and their boot check, in place. Which of MFA's
     * codes take that path is the challenge gateway adapter's to judge, code by
     * code, as each is sent.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return bool
     */
    public function routesFactorCodes(Repository $config): bool
    {
        return $this->isRouted($config) || $this->container->bound(OneTimeCodeSender::class);
    }

    /**
     * Whether the channel's gateway is available: named in configuration, or
     * bound in the container.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Channel  $channel
     * @return bool
     */
    public function isAvailable(Repository $config, Channel $channel): bool
    {
        return self::isNamed($config, $channel) || $this->container->bound(self::contract($channel));
    }

    /**
     * Whether the application names a class for the channel's gateway: any text
     * that is not blank. Whether it names a gateway is the resolver's to check,
     * and fails closed there.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Channel  $channel
     * @return bool
     */
    public static function isNamed(Repository $config, Channel $channel): bool
    {
        $class = $config->get(self::GATEWAYS . $channel->value);

        return is_string($class) && trim($class) !== '';
    }

    /**
     * The contract the channel's gateway implements.
     *
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Channel  $channel
     * @return class-string<\SineMacula\Laravel\Iam\Contracts\EmailGateway|\SineMacula\Laravel\Iam\Contracts\SmsGateway>
     */
    public static function contract(Channel $channel): string
    {
        return match ($channel) {
            Channel::EMAIL => EmailGateway::class,
            Channel::SMS   => SmsGateway::class,
        };
    }

    /**
     * Whether every gateway `iam.delivery.types` routes an identifier type to
     * is available. A delivery configuration that holds no routes (one that
     * sets `iam.delivery` without them replaces the shipped block whole) is
     * read with the shipped ones. A map that is empty, not a map, or routes a
     * type to a gateway this package does not know routes nothing.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return bool
     */
    private function isRouted(Repository $config): bool
    {
        $types = $config->get(self::TYPES) ?? self::DEFAULT_TYPES;

        if (!is_array($types) || $types === []) {
            return false;
        }

        foreach ($types as $gateway) {

            $channel = is_string($gateway) ? Channel::tryFrom($gateway) : null;

            if ($channel === null || !$this->isAvailable($config, $channel)) {
                return false;
            }
        }

        return true;
    }
}
