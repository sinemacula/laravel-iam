<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Mfa\MfaServiceProvider;
use SineMacula\Laravel\Sso\SsoServiceProvider;

/**
 * Creates the tables a test of the adapters between `laravel-authentication`
 * and SSO runs against, on the shared storage connection: every migration
 * `MigratesMembers` runs (`laravel-authentication`'s, MFA's and the fixtures'),
 * and every one SSO ships, which it only publishes and never loads itself. It
 * is used in place of `MigratesMembers`, never beside it.
 *
 * As with `MigratesMembers`, the tables are created before each test and
 * dropped after it, never inside a transaction the test runs in, so a test may
 * commit, race two connections or run at an isolation level of its own; SSO's
 * starts and completions refuse to run inside one anyway.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \Tests\TestCase
 */
trait MigratesSso
{
    /**
     * Run every member's migrations the test needs, SSO's among them, and the
     * fixtures', rolled back once the test ends.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(dirname(__DIR__) . '/Fixtures/database/migrations');

        foreach ([AuthenticationServiceProvider::class, MfaServiceProvider::class, SsoServiceProvider::class] as $provider) {

            $file = (new \ReflectionClass($provider))->getFileName();

            assert(is_string($file));

            $this->loadMigrationsFrom(dirname($file, 2) . '/database/migrations');
        }
    }
}
