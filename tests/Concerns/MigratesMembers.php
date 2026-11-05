<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Mfa\MfaServiceProvider;

/**
 * Creates the tables a test of the adapters between `laravel-authentication`
 * and MFA runs against, on the shared storage connection: every migration
 * either member ships (neither loads its own), and the fixtures' people table.
 *
 * The tables are created before each test and dropped after it, never inside a
 * transaction the test runs in, so a test may commit, race two connections or
 * run at an isolation level of its own, on SQLite, MySQL and PostgreSQL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \Tests\TestCase
 */
trait MigratesMembers
{
    /**
     * Run every member's migrations the test needs, and the fixtures', rolled
     * back once the test ends.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void
    {
        foreach (self::migrationPaths() as $path) {
            $this->loadMigrationsFrom($path);
        }
    }

    /**
     * Return the directories the migrations are read from: each member's own,
     * found beside its service provider, and the fixtures'.
     *
     * @return list<string>
     */
    private static function migrationPaths(): array
    {
        $paths = [dirname(__DIR__) . '/Fixtures/database/migrations'];

        foreach ([AuthenticationServiceProvider::class, MfaServiceProvider::class] as $provider) {

            $file = (new \ReflectionClass($provider))->getFileName();

            assert(is_string($file));

            $paths[] = dirname($file, 2) . '/database/migrations';
        }

        return $paths;
    }
}
