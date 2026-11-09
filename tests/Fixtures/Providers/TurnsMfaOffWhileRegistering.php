<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Providers;

use Illuminate\Support\Facades\Config;
use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;

/**
 * An application's provider that turns the MFA capability's switch off from its
 * `register()`, before or after this package's provider registers, wherever a
 * test puts it in the provider order.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class TurnsMfaOffWhileRegistering extends ServiceProvider
{
    /**
     * Turn the MFA capability's switch off.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        Config::set(MfaSeams::SWITCH, false);
    }
}
