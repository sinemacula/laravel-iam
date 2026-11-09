<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Providers;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Authentication\Context\ContextContributors;

/**
 * An application's provider that registers a contributor of its own under the
 * `mfa` namespace of `laravel-authentication`'s authentication context from its
 * `boot()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RegistersAnMfaContributor extends ServiceProvider
{
    /** @var string The application's own contributor's abstract. */
    public const string CONTRIBUTOR = 'application.mfa-contributor';

    /**
     * Register the application's contributor under `mfa`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function boot(): void
    {
        $this->app->make(ContextContributors::class)->register('mfa', self::CONTRIBUTOR);
    }
}
