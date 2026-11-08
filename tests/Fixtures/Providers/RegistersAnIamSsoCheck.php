<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Providers;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Sso\Config\Checks\FeaturesCheck;
use SineMacula\Laravel\Sso\Config\ConfigurationChecks;

/**
 * An application's provider, registered after the packages' as Laravel
 * registers an application's providers, that registers a check of its own under
 * `iam` with SSO's configuration checks from its `register()`, as SSO's
 * `ConfigurationChecks` recommends.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RegistersAnIamSsoCheck extends ServiceProvider
{
    /** @var class-string<\SineMacula\Laravel\Sso\Contracts\ConfigurationCheck> The application's own check. */
    public const string CHECK = FeaturesCheck::class;

    /**
     * Register the application's check under `iam` once SSO's checks are
     * resolved.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        $this->callAfterResolving(ConfigurationChecks::class, static function (ConfigurationChecks $checks): void {
            $checks->add('iam', self::CHECK);
        });
    }
}
