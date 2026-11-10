<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Checks;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\OneTimeCodeSender;
use SineMacula\Laravel\Iam\Checks\Contracts\Check;
use SineMacula\Laravel\Iam\Delivery\DeliverySeams;
use SineMacula\Laravel\Iam\Delivery\EmailSenderAdapter;
use SineMacula\Laravel\Iam\Delivery\Enums\Channel;
use SineMacula\Laravel\Iam\Delivery\OneTimeCodeSenderAdapter;
use SineMacula\Laravel\Iam\Delivery\SmsSenderAdapter;
use SineMacula\Laravel\Mfa\Codes\NullEmailSender;
use SineMacula\Laravel\Mfa\Codes\NullSmsSender;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;
use SineMacula\Laravel\Mfa\Contracts\SmsSender;

/**
 * The code senders are bound while a code method is allowed (IAM-10.2,
 * IAM-3.13), from the side of the gateways this package delivers through.
 *
 * Each member checks its own sender: `laravel-authentication` that a
 * `OneTimeCodeSender` is bound while a guard allows a code sign-in method, MFA
 * that its SMS and email senders are off their null defaults while an
 * application enables `sms` or `email`. This adds what crosses them: the
 * application's gateway behind this package's senders.
 *
 * - Every route in `iam.delivery.types` names a channel this package delivers
 *   on (`email`, `sms`).
 * - Every code sign-in method a `jwt` guard allows has its identifier type
 *   routed to a channel while `laravel-authentication`'s sender is this
 *   package's or unbound: a code of a type the routes leave out can be
 *   delivered by no gateway, and `laravel-authentication`'s own check sees a
 *   sender bound and passes.
 * - A gateway named in `iam.delivery.email` or `iam.delivery.sms`, where the
 *   application binds none of its own, is a class implementing the channel's
 *   contract. The class is not built, so a check never runs the application's
 *   gateway.
 * - A channel has a gateway, bound or named, while something sends on it
 *   through this package: a `jwt` guard allowing `email_code` or `phone_code`,
 *   routed to the channel by `iam.delivery.types`, while
 *   `laravel-authentication`'s sender is this package's or unbound; an MFA
 *   application enabling `sms` or `email` while MFA's sender of that channel is
 *   this package's, MFA's null default, or unbound. A sender the application
 *   bound itself needs no gateway of this package's.
 *
 * Whether a guard allows a code method is asked of `laravel-authentication`'s
 * application policy, which answers from configuration; a guard it cannot
 * answer for is left to `authentication:check`, which reports it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SendersCheck implements Check
{
    /** @var array<string, string> Each of `laravel-authentication`'s code sign-in methods, with the identifier type its code is sent to. */
    public const array CODE_METHODS = ['email_code' => 'email', 'phone_code' => 'phone'];

    /** @var string Why a channel something sends on with no gateway is refused. */
    private const string NO_GATEWAY = '%s send on %s with no gateway: name one in `%s`, or bind %s.';

    /** @var string Why a code method whose identifier type no route names is refused. */
    private const string UNROUTED = 'Guards [%s] allow `%s`, but `%s` routes no `%s` type to a channel.';

    /** @var string The guard driver whose guards sign people in with codes. */
    private const string JWT = 'jwt';

    /** @var string The key of MFA's applications. */
    private const string APPLICATIONS = 'mfa.applications';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \SineMacula\Laravel\Iam\Checks\SeamHolders  $holders
     */
    public function __construct(

        /** The container the senders and the gateways are bound in. */
        private Container $container,

        /** The configuration the routes, the gateways, the guards and MFA's applications are read from. */
        private Repository $config,

        /** Names the class each sender's live binding answers with. */
        private SeamHolders $holders,
    ) {}

    /**
     * The subject the findings are reported under.
     *
     * @return string
     */
    #[\Override]
    public function subject(): string
    {
        return 'senders';
    }

    /**
     * The check always applies: what it requires follows what is allowed.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return true;
    }

    /**
     * The routes, each code method's route, then each channel's named gateway
     * and its gateway while something sends on it.
     *
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function checks(): array
    {
        $checks = [fn () => $this->assertRoutes()];

        foreach (self::CODE_METHODS as $method => $type) {
            $checks[] = fn () => $this->assertRouted($method, $type);
        }

        foreach (Channel::cases() as $channel) {
            $checks[] = fn () => $this->assertNamedGateway($channel);
            $checks[] = fn () => $this->assertGateway($channel);
        }

        return $checks;
    }

    /**
     * Refuse a route that names no channel this package delivers on.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private function assertRoutes(): void
    {
        $types = $this->config->get(DeliverySeams::TYPES) ?? DeliverySeams::DEFAULT_TYPES;

        if (!is_array($types)) {
            throw new \InvalidArgumentException(sprintf('`%s` must map identifier types to channels.', DeliverySeams::TYPES));
        }

        foreach ($types as $type => $channel) {

            if (!is_string($channel) || Channel::tryFrom($channel) === null) {
                throw new \InvalidArgumentException(sprintf('`%s.%s` must name a channel: %s.', DeliverySeams::TYPES, $type, self::channels()));
            }
        }
    }

    /**
     * Refuse a code method guards allow whose identifier type no route names,
     * while `laravel-authentication`'s sender is this package's or unbound.
     * Routes that are no map are refused by `assertRoutes()`.
     *
     * @param  string  $method
     * @param  string  $type
     * @return void
     *
     * @throws \LogicException
     */
    private function assertRouted(string $method, string $type): void
    {
        $types = $this->config->get(DeliverySeams::TYPES) ?? DeliverySeams::DEFAULT_TYPES;

        if (!is_array($types) || isset($types[$type]) || !$this->isThisPackages(OneTimeCodeSender::class, [OneTimeCodeSenderAdapter::class])) {
            return;
        }

        $guards = $this->guardsAllowing($method);

        if ($guards === []) {
            return;
        }

        throw new \LogicException(sprintf(self::UNROUTED, implode(', ', $guards), $method, DeliverySeams::TYPES, $type));
    }

    /**
     * Refuse a gateway named for the channel, where the application binds none
     * of its own, that is no class implementing the channel's contract.
     *
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Channel  $channel
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private function assertNamedGateway(Channel $channel): void
    {
        $contract = DeliverySeams::contract($channel);
        $key      = DeliverySeams::GATEWAYS . $channel->value;
        $named    = $this->config->get($key);

        if ($this->container->bound($contract) || !DeliverySeams::isNamed($this->config, $channel) || (is_string($named) && is_subclass_of($named, $contract))) {
            return;
        }

        throw new \InvalidArgumentException(sprintf('`%s` must name a class implementing %s.', $key, $contract));
    }

    /**
     * Refuse a channel something sends on through this package with no gateway
     * bound or named.
     *
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Channel  $channel
     * @return void
     *
     * @throws \LogicException
     */
    private function assertGateway(Channel $channel): void
    {
        $senders = [...$this->codeSenders($channel), ...$this->factorSenders($channel)];

        if ($senders === [] || (new DeliverySeams($this->container))->isAvailable($this->config, $channel)) {
            return;
        }

        $key = DeliverySeams::GATEWAYS . $channel->value;

        throw new \LogicException(sprintf(self::NO_GATEWAY, implode(' and ', $senders), $channel->value, $key, DeliverySeams::contract($channel)));
    }

    /**
     * What sends `laravel-authentication`'s sign-in codes on the channel
     * through this package: the guards allowing a code method routed to it. A
     * method routed nowhere is refused by `assertRouted()`.
     *
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Channel  $channel
     * @return list<string>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function codeSenders(Channel $channel): array
    {
        if (!$this->isThisPackages(OneTimeCodeSender::class, [OneTimeCodeSenderAdapter::class])) {
            return [];
        }

        $types  = $this->config->get(DeliverySeams::TYPES) ?? DeliverySeams::DEFAULT_TYPES;
        $guards = [];

        foreach (self::CODE_METHODS as $method => $type) {

            if (!is_array($types) || ($types[$type] ?? null) !== $channel->value) {
                continue;
            }

            $guards = [...$guards, ...$this->guardsAllowing($method)];
        }

        $guards = array_unique($guards);

        return $guards === [] ? [] : [sprintf('Guards [%s]', implode(', ', $guards))];
    }

    /**
     * What sends MFA's factor codes on the channel through this package: the
     * MFA applications enabling it as a factor type.
     *
     * @param  \SineMacula\Laravel\Iam\Delivery\Enums\Channel  $channel
     * @return list<string>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function factorSenders(Channel $channel): array
    {
        $sender = match ($channel) {
            Channel::EMAIL => [EmailSender::class, EmailSenderAdapter::class, NullEmailSender::class],
            Channel::SMS   => [SmsSender::class, SmsSenderAdapter::class, NullSmsSender::class],
        };

        if (!$this->isThisPackages($sender[0], [$sender[1], $sender[2]])) {
            return [];
        }

        $applications = $this->config->get(self::APPLICATIONS);
        $enabling     = [];

        foreach (is_array($applications) ? $applications : [] as $name => $settings) {

            $types = is_array($settings) ? $settings['types'] ?? null : null;

            if (!is_array($types) || !in_array($channel->value, $types, true)) {
                continue;
            }

            $enabling[] = $name;
        }

        return $enabling === [] ? [] : [sprintf('MFA applications [%s]', implode(', ', $enabling))];
    }

    /**
     * The `jwt` guards whose application policy allows the method; a guard the
     * policy cannot answer for is left to `authentication:check`.
     *
     * @param  string  $method
     * @return list<string>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function guardsAllowing(string $method): array
    {
        $guards = $this->config->get('auth.guards');
        $policy = $this->container->make(ApplicationPolicy::class);
        $found  = [];

        foreach (is_array($guards) ? $guards : [] as $name => $guard) {

            if (!is_array($guard) || ($guard['driver'] ?? null) !== self::JWT) {
                continue;
            }

            $guardName = (string) $name;

            try {
                $allowed = $policy->allowsMethod($guardName, $method);
            } catch (\InvalidArgumentException) {
                continue;
            }

            if (!$allowed) {
                continue;
            }

            $found[] = $guardName;
        }

        return $found;
    }

    /**
     * Whether the sender is unbound, or bound to one of the classes given, this
     * package's or the member's default, and so delivers through this package's
     * gateways or would once bound.
     *
     * @param  string  $abstract
     * @param  list<class-string>  $classes
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function isThisPackages(string $abstract, array $classes): bool
    {
        return !$this->container->bound($abstract) || in_array($this->holders->of($this->container, $abstract), $classes, true);
    }

    /**
     * The channels this package delivers on, for a message.
     *
     * @return string
     */
    private static function channels(): string
    {
        return implode(' or ', array_column(Channel::cases(), 'value'));
    }
}
