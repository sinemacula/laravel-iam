<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Checks;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Context\ContextContributors;
use SineMacula\Laravel\Iam\Checks\Contracts\Check;
use SineMacula\Laravel\Iam\Sso\SsoSeams;
use SineMacula\Laravel\Sso\Sessions\AuthenticationContext;

/**
 * The `sso` namespace of `laravel-authentication`'s authentication context is
 * registered while SSO is in use (IAM-10.2, IAM-4.8).
 *
 * This package registers its contributor there while its SSO capability's
 * switch is on; with the switch off, the application registers its own. Either
 * way, a session established through SSO needs one, or its provenance never
 * reaches the context. Nothing is required while SSO is not in use, since no
 * session is established through it. The `mfa` namespace joins with the `mfa`
 * contributor (M10, IAM-13.6).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ContextNamespacesCheck implements Check
{
    /** @var string Why a namespace nobody registered is refused. */
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
     * The check applies while SSO is in use.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return SsoSeams::isInUse($this->config);
    }

    /**
     * The `sso` namespace is registered.
     *
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function checks(): array
    {
        return [
            function (): void {
                $this->assertRegistered(AuthenticationContext::NAMESPACE);
            },
        ];
    }

    /**
     * Refuse a namespace no contributor is registered under.
     *
     * @param  string  $namespace
     * @return void
     *
     * @throws \LogicException
     */
    private function assertRegistered(string $namespace): void
    {
        if (array_key_exists($namespace, $this->container->make(ContextContributors::class)->registered())) {
            return;
        }

        throw new \LogicException(sprintf(self::UNREGISTERED, $namespace, SsoSeams::SWITCH));
    }
}
