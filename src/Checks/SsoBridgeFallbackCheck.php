<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Checks;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Iam\Checks\Contracts\Check;
use SineMacula\Laravel\Iam\Checks\Sso\SsoBridgeCheck;
use SineMacula\Laravel\Iam\Sso\SsoSeams;

/**
 * This package's check of SSO's side (`Sso\SsoBridgeCheck`), run by `iam:check`
 * itself while SSO is in use and `sso:check` does not run it (IAM-2.5,
 * IAM-10.2).
 *
 * `sso:check` runs the bridge only while SSO's checker, as it is resolved, is
 * SSO's own class built with the bridge under `iam`
 * (`SsoCheckRegistration::isInForce()`). An application that keeps a check of
 * its own under that subject, which the registration leaves in place, or binds
 * a checker of its own (SSO's class built from a list of its own included),
 * takes the bridge out of SSO's check, and with it every SSO application's
 * `external_provider` sign-in method, every application's `unlinked_handoffs`
 * and the mandatory seams of SSO's flows. This check then runs every one of the
 * bridge's checks, so none of them goes unchecked; while the bridge is in
 * force, or SSO is not in use, it does not apply, so each is reported once.
 *
 * It reads configuration and the container only, as the bridge does, and
 * building it reads nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SsoBridgeFallbackCheck implements Check
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \SineMacula\Laravel\Iam\Checks\Sso\SsoBridgeCheck  $bridge
     */
    public function __construct(

        /** The container SSO's checker is resolved from. */
        private Container $container,

        /** The configuration whether SSO is in use is read from. */
        private Repository $config,

        /** This package's check of SSO's side. */
        private SsoBridgeCheck $bridge,
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
     * The check applies while SSO is in use and `sso:check` does not run the
     * bridge; where whether it does cannot be read, it applies, so the bridge
     * runs rather than go unrun.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return SsoSeams::isInUse($this->config) && !SsoCheckRegistration::isInForce($this->container);
    }

    /**
     * Every check of the bridge's.
     *
     * @return list<\Closure(): mixed>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    public function checks(): array
    {
        return $this->bridge->checks();
    }
}
