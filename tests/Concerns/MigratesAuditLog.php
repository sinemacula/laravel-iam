<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use SineMacula\Laravel\AuditLog\AuditLogServiceProvider;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Mfa\MfaServiceProvider;
use SineMacula\Laravel\Sso\SsoServiceProvider;

/**
 * Creates the tables a test of the audit trail runs against, on the shared
 * storage connection: every migration `MigratesSso` runs
 * (`laravel-authentication`'s, MFA's, SSO's and the fixtures'), and every one
 * audit-log ships, which it only publishes and never loads itself, so its
 * entries are written to and read from its own tables, not a fake. It is used
 * in place of `MigratesMembers` or `MigratesSso`, never beside either.
 *
 * As with `MigratesMembers`, the tables are created before each test and
 * dropped after it, never inside a transaction the test runs in, so a test may
 * commit, open a transaction of its own or run at an isolation level of its
 * own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \Tests\TestCase
 */
trait MigratesAuditLog
{
    /**
     * Run every member's migrations, audit-log's among them, and the fixtures',
     * rolled back once the test ends.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(dirname(__DIR__) . '/Fixtures/database/migrations');

        foreach ([AuthenticationServiceProvider::class, MfaServiceProvider::class, SsoServiceProvider::class, AuditLogServiceProvider::class] as $provider) {

            $file = (new \ReflectionClass($provider))->getFileName();

            assert(is_string($file));

            $this->loadMigrationsFrom(dirname($file, 2) . '/database/migrations');
        }
    }
}
