<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Providers;

use Illuminate\Support\Facades\Config;
use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Iam\Sso\SsoSeams;

/**
 * An application's provider that turns the SSO capability's switch on from its
 * `register()`, before or after this package's provider registers, wherever a
 * test puts it in the provider order.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class TurnsSsoOnWhileRegistering extends ServiceProvider
{
    /**
     * Turn the SSO capability's switch on.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        Config::set(SsoSeams::SWITCH, true);
    }
}
