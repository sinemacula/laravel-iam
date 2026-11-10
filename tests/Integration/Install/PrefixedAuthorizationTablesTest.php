<?php

declare(strict_types = 1);

namespace Tests\Integration\Install;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Iam\Console\InstallCommand;
use SineMacula\Laravel\Iam\Install\AuthorizationTablePrefix;
use Tests\Concerns\NamesAuthorizationTables;
use Tests\Concerns\UsesScratchDirectory;
use Tests\TestCase;

/**
 * Integration tests for the prefixed names `iam:install` writes for
 * `laravel-authorization`'s tables (IAM-2.4): with the longest prefix allowed,
 * every one of `laravel-authorization`'s published migrations creates its table
 * under the prefixed name, and every table, index and foreign key name it
 * derives stays within MySQL's and PostgreSQL's limits.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationTablePrefix::class)]
final class PrefixedAuthorizationTablesTest extends TestCase
{
    use NamesAuthorizationTables, UsesScratchDirectory;

    /**
     * Destroy the application, then delete the test's directory.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        parent::tearDown();

        $this->deleteScratch();
    }

    /**
     * With the longest prefix allowed, `laravel-authorization`'s published
     * migrations create every table under its prefixed name, and drop them.
     *
     * @return void
     */
    public function testTheLongestPrefixMigratesEveryTable(): void
    {
        $prefix = str_repeat('p', AuthorizationTablePrefix::MAX_LENGTH - 1) . '_';

        self::assertSame(0, Artisan::call(InstallCommand::NAME, ['--no-interaction' => true, '--prefix' => $prefix]));

        /** @var array{tables: array<string, string>} $configuration */
        $configuration = require $this->scratch('config/authorization.php');

        $config = $this->app?->make(ConfigRepository::class);

        assert($config instanceof ConfigRepository);

        $config->set('authorization.tables', $configuration['tables']);

        $migrations = array_map(fn (string $name): string => $this->scratch('database/migrations/' . $name), self::authorizationMigrations());
        $ran        = [];

        self::assertNotSame([], $migrations);

        try {
            foreach ($migrations as $file) {
                $migration = require $file;

                assert($migration instanceof Migration && method_exists($migration, 'up'));

                $migration->up();

                $ran[] = $migration;
            }

            self::assertSame(self::prefixedAuthorizationTables($prefix), $configuration['tables']);

            foreach ($configuration['tables'] as $key => $table) {
                self::assertTrue(Schema::hasTable($table), $table);
                self::assertFalse(Schema::hasTable($key), $key);
            }
        } finally {
            foreach (array_reverse($ran) as $migration) {
                assert(method_exists($migration, 'down'));

                $migration->down();
            }
        }

        foreach ($configuration['tables'] as $table) {
            self::assertFalse(Schema::hasTable($table), $table);
        }
    }

    /**
     * Point the application's configuration, database and language directories
     * at the test's own before any provider registers.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function resolveApplicationConfiguration(mixed $app): void
    {
        parent::resolveApplicationConfiguration($app);

        $app->useConfigPath($this->scratch('config'));
        $app->useDatabasePath($this->scratch('database'));
        $app->useLangPath($this->scratch('lang'));
    }
}
