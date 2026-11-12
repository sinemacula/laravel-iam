<?php

declare(strict_types = 1);

namespace Tests\Integration\Install;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Iam\Console\InstallCommand;
use Tests\Concerns\UsesScratchDirectory;
use Tests\TestCase;

/**
 * Integration tests for the `laravel-authorization` table prefix `iam:install`
 * writes (IAM-2.4).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(InstallCommand::class)]
final class PrefixedAuthorizationTablesTest extends TestCase
{
    use UsesScratchDirectory;

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
        $prefix = str_repeat('p', 15) . '_';

        self::assertSame(0, Artisan::call(InstallCommand::NAME, ['--no-interaction' => true, '--prefix' => $prefix]));

        /** @var array{tables: array<string, string>} $configuration */
        $configuration = require $this->scratch('config/authorization.php');

        $config = $this->app?->make(ConfigRepository::class);

        assert($config instanceof ConfigRepository);

        $config->set('authorization.tables', $configuration['tables']);

        $shipped    = glob(dirname((string) (new \ReflectionClass(AuthorizationServiceProvider::class))->getFileName(), 2) . '/database/migrations/*.php') ?: [];
        $migrations = array_map(fn (string $file): string => $this->scratch('database/migrations/' . basename($file)), $shipped);
        $tables     = array_values(array_diff_key($configuration['tables'], ['prefix' => '']));
        $ran        = [];

        self::assertNotSame([], $migrations);

        try {
            foreach ($migrations as $file) {
                $migration = require $file;

                assert($migration instanceof Migration && method_exists($migration, 'up'));

                $migration->up();

                $ran[] = $migration;
            }

            self::assertSame($prefix, $configuration['tables']['prefix']);

            foreach ($tables as $table) {
                self::assertTrue(Schema::hasTable($prefix . $table), $prefix . $table);
                self::assertFalse(Schema::hasTable($table), $table);
            }
        } finally {
            foreach (array_reverse($ran) as $migration) {
                assert(method_exists($migration, 'down'));

                $migration->down();
            }
        }

        foreach ($tables as $table) {
            self::assertFalse(Schema::hasTable($prefix . $table), $prefix . $table);
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
