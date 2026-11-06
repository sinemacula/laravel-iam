<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Providers;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\ServiceProvider;

/**
 * An application's provider that, in its `register()`, has the test's guard
 * carry its refresh token in a cookie, as a single-page application served from
 * its own site does, and declares a second session guard that carries it in the
 * body.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CarriesRefreshTokensInACookie extends ServiceProvider
{
    /** @var string The guard whose refresh token travels in a cookie. */
    public const string GUARD = 'api';

    /** @var string The session guard whose refresh token travels in the body. */
    public const string BODY_GUARD = 'mobile';

    /**
     * Have the guard carry its refresh token in a cookie, and declare a second
     * session guard, first, that carries it in the body.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    public function register(): void
    {
        $config = $this->app->make(Repository::class);

        /** @var array<string, mixed> $guards */
        $guards = $config->get('auth.guards');

        /** @var array<string, mixed> $guard */
        $guard = $guards[self::GUARD];

        $config->set('auth.guards', [
            self::BODY_GUARD => [...$guard, 'refresh_token' => ['transport' => 'body']],
            ...$guards,
            self::GUARD => [...$guard, 'refresh_token' => ['transport' => 'cookie', 'cookie' => ['path' => '/auth/refresh']]],
        ]);
    }
}
