<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Checks\Sso;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Sessions\SignInMethodManager;
use SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams;
use SineMacula\Laravel\Iam\Checks\Contracts\Check;
use SineMacula\Laravel\Iam\Checks\MandatorySeamsCheck;
use SineMacula\Laravel\Iam\Sso\SsoSeams;
use SineMacula\Laravel\Iam\Tenancy\TenancySeams;

/**
 * Checks, while SSO is in use, that each SSO application allows
 * `external_provider` and keeps `unlinked_handoffs` off, and that SSO's
 * mandatory seams are bound.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SsoBridgeCheck implements Check
{
    /** @var list<class-string<\SineMacula\Laravel\Iam\Bindings\Contracts\ProvidesSeams>> The capabilities whose mandatory seams this check covers. */
    public const array CAPABILITIES = [SsoSeams::class, TenancySeams::class];

    /** @var string The key of SSO's applications. */
    private const string APPLICATIONS = 'sso.applications';

    /** @var string The failure for a guard that does not allow external sign-in. */
    private const string NO_EXTERNAL_SIGN_IN = '`%s.%s` is served by SSO, but its guard does not list `%s` among laravel-authentication\'s sign-in methods.';

    /** @var list<mixed> The values SSO reads a switch as off from. */
    private const array OFF = [null, false, 0, '0', 'false'];

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \SineMacula\Laravel\Iam\Checks\MandatorySeamsCheck  $seams
     */
    public function __construct(

        /** The container the application policy and capabilities are resolved from. */
        private Container $container,

        /** The configuration SSO's and laravel-authentication's settings are read from. */
        private Repository $config,

        /** Checks the mandatory seams of SSO's flows. */
        private MandatorySeamsCheck $seams,
    ) {}

    /**
     * The subject the findings are reported under.
     *
     * @return string
     */
    #[\Override]
    public function subject(): string
    {
        return 'sso';
    }

    /**
     * The checks apply while SSO is in use.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return SsoSeams::isInUse($this->config);
    }

    /**
     * Each application's sign-in method and handoffs, then the mandatory seams.
     *
     * @return list<\Closure(): mixed>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    public function checks(): array
    {
        $checks = [];

        foreach ($this->applications() as $application) {
            $checks[] = fn () => $this->assertExternalSignIn($application);
            $checks[] = fn () => $this->assertNoUnlinkedHandoffs($application);
        }

        $capabilities = array_map(fn (string $capability): ProvidesSeams => $this->container->make($capability), self::CAPABILITIES);

        return [...$checks, ...$this->seams->checksFor(...$capabilities)];
    }

    /**
     * Refuse an application whose guard does not allow external sign-in.
     *
     * @param  string  $application
     * @return void
     *
     * @throws \LogicException
     */
    private function assertExternalSignIn(string $application): void
    {
        if ($this->container->make(ApplicationPolicy::class)->allowsMethod($application, SignInMethodManager::EXTERNAL_METHOD)) {
            return;
        }

        throw new \LogicException(sprintf(self::NO_EXTERNAL_SIGN_IN, self::APPLICATIONS, $application, SignInMethodManager::EXTERNAL_METHOD));
    }

    /**
     * Refuse an application whose unlinked handoffs are on.
     *
     * @param  string  $application
     * @return void
     *
     * @throws \LogicException
     */
    private function assertNoUnlinkedHandoffs(string $application): void
    {
        $key = self::APPLICATIONS . '.' . $application . '.unlinked_handoffs';

        if (in_array($this->config->get($key), self::OFF, true)) {
            return;
        }

        throw new \LogicException(sprintf('`%s` must stay off under laravel-iam: an unlinked result is provisioned or refused, never handed off.', $key));
    }

    /**
     * The applications SSO serves.
     *
     * @return list<string>
     */
    private function applications(): array
    {
        $applications = $this->config->get(self::APPLICATIONS);

        return is_array($applications) ? array_map(strval(...), array_keys($applications)) : [];
    }
}
