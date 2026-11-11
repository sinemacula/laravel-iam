<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Checks;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Context\ContextContributors;
use SineMacula\Laravel\Iam\Checks\Contracts\Check;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use SineMacula\Laravel\Iam\Sso\SsoSeams;
use SineMacula\Laravel\Mfa\Context\AuthenticationContextContributor as MfaContributor;
use SineMacula\Laravel\Sso\Sessions\AuthenticationContext;

/**
 * The authentication context has an `mfa` contributor, and an `sso` one while
 * SSO is in use (IAM-10.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ContextNamespacesCheck implements Check
{
    /** @var string Why a namespace nobody registered is refused, and the switch that registers this package's contributor there. */
    private const string UNREGISTERED = 'No contributor is registered under the `%s` namespace of the authentication context; '
        . 'turn `%s` on, or register your own.';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** The container `laravel-authentication`'s contributors are resolved from. */
        private Container $container,

        /** The configuration SSO's use is read from. */
        private Repository $config,
    ) {}

    /**
     * The subject the findings are reported under.
     *
     * @return string
     */
    #[\Override]
    public function subject(): string
    {
        return 'context';
    }

    /**
     * The check always applies: the `mfa` namespace is always required.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return true;
    }

    /**
     * The `mfa` namespace is registered, and the `sso` namespace while SSO is
     * in use.
     *
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function checks(): array
    {
        $checks = [
            function (): void {
                $this->assertRegistered(MfaContributor::NAMESPACE, MfaSeams::SWITCH);
            },
        ];

        if (SsoSeams::isInUse($this->config)) {
            $checks[] = function (): void {
                $this->assertRegistered(AuthenticationContext::NAMESPACE, SsoSeams::SWITCH);
            };
        }

        return $checks;
    }

    /**
     * Refuse a namespace no contributor is registered under, naming the switch
     * that registers this package's contributor there.
     *
     * @param  string  $namespace
     * @param  string  $switch
     * @return void
     *
     * @throws \LogicException
     */
    private function assertRegistered(string $namespace, string $switch): void
    {
        if (array_key_exists($namespace, $this->container->make(ContextContributors::class)->registered())) {
            return;
        }

        throw new \LogicException(sprintf(self::UNREGISTERED, $namespace, $switch));
    }
}
