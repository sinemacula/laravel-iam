<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Console;

use Illuminate\Console\Command;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Authorization\Config\TableNames;
use SineMacula\Laravel\Iam\Install\MigrationLedger;
use Symfony\Component\Console\Attribute\AsCommand;

/**
 * `iam:install`: publishes every member's files and this package's
 * configuration, and lists what is still owed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[AsCommand(name: self::NAME)]
final class InstallCommand extends Command
{
    /** @var string The command's name. */
    public const string NAME = 'iam:install';

    /** @var string The installation guide every owed item points at. */
    public const string GUIDE = 'https://github.com/sinemacula/laravel-iam/blob/master/docs/guides/installation.md';

    /** @var list<string> The configuration and language tags to publish. */
    private const array TAGS = [
        'authentication-config',
        'authorization-config',
        'authorization-lang',
        'mfa-config',
        'mfa-lang',
        'sso-config',
        'sso-lang',
        'audit-log-config',
        'audit-log-lang',
        'iam-config',
    ];

    /** @var array<string, string> The migration tags, with the namespace each one's migrations name. */
    private const array MIGRATIONS = [
        'authentication-migrations' => 'SineMacula\Laravel\Authentication\\',
        'authorization-migrations'  => 'SineMacula\Laravel\Authorization\\',
        'mfa-migrations'            => 'SineMacula\Laravel\Mfa\\',
        'sso-migrations'            => 'SineMacula\Laravel\Sso\\',
        'audit-log-migrations'      => 'SineMacula\Laravel\AuditLog\\',
    ];

    /** @var array<string, string> What the application still owes, with the guide's section on it. */
    private const array OWED = [
        'Run `php artisan migrate`'                                                        => 'the-storage-connection',
        'Add every `jwt` and `api_key` guard to `audit-log.capture.laravel.except_guards`' => 'the-audit-log-configuration',
        'Turn `audit-log.definitions.require_registered` on'                               => 'the-audit-log-configuration',
        'Declare MFA\'s and SSO\'s freshness operations for their guards'                  => 'guards-and-applications',
        'Bind the contracts the package leaves to you, and add the routes'                 => 'what-you-still-owe',
        'Call `Iam::schedule()`, and run the scheduler and a queue worker'                 => 'what-you-still-owe',
        'Run `php artisan iam:check` on every deploy'                                      => 'checking',
    ];

    /** @var string The question whether to prefix `laravel-authorization`'s tables. */
    private const string PREFIX_QUESTION = 'Prefix laravel-authorization\'s tables (roles, permissions, policies and the grant tables), whose names may collide with your own?';

    /** @var string The name and signature of the console command. */
    protected $signature = self::NAME . ' {--prefix= : Prefix laravel-authorization\'s table names (for example "authorization_")}';

    /** @var string The console command description. */
    protected $description = 'Publish every member\'s configuration, language files and migrations, and say what the application still owes';

    /**
     * Execute the console command.
     *
     * @param  \Illuminate\Filesystem\Filesystem  $files
     * @return int
     *
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public function handle(Filesystem $files): int
    {
        $ledger        = new MigrationLedger($files);
        $configuration = $this->prefixableConfiguration($files, $ledger);
        $prefix        = $this->tablePrefix($configuration !== null);

        if ($prefix !== null && !TableNames::isValidPrefix($prefix)) {
            $this->error('The table prefix must be lower-case letters, digits and underscores, start with a letter and be at most 16 characters long.');

            return self::INVALID;
        }

        $missing = array_filter([...self::TAGS, ...array_keys(self::MIGRATIONS)], static fn (string $tag): bool => self::pathsOf($tag) === []);

        foreach ($missing as $tag) {
            $this->error("No provider registered the `{$tag}` tag.");
        }

        $this->call('vendor:publish', ['--tag' => self::TAGS]);

        if ($prefix !== null) {
            $this->prefixTables($files, $configuration, $prefix);
        }

        $this->publishMigrations($files, $ledger);

        $this->newLine();
        $this->line('Still to do:');

        foreach (self::OWED as $item => $section) {
            $this->line(sprintf(' - %s: %s#%s', $item, self::GUIDE, $section));
        }

        return $missing === [] ? self::SUCCESS : self::FAILURE;
    }

    /**
     * Publish each member's migration not already published under any
     * timestamp.
     *
     * @param  \Illuminate\Filesystem\Filesystem  $files
     * @param  \SineMacula\Laravel\Iam\Install\MigrationLedger  $ledger
     * @return void
     *
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    private function publishMigrations(Filesystem $files, MigrationLedger $ledger): void
    {
        foreach (self::MIGRATIONS as $tag => $namespace) {

            foreach (self::migrationsOf($files, $tag) as $source => $destination) {

                $copy = $files->exists($destination) ? $destination : $ledger->copyOf($destination, $namespace);

                if ($copy !== null) {
                    $this->line(sprintf('Kept %s, published as %s.', basename($destination), basename($copy)));

                    continue;
                }

                $files->ensureDirectoryExists(dirname($destination));
                $files->copy($source, $destination);

                $this->line('Published ' . basename($destination) . '.');
            }
        }
    }

    /**
     * The `--prefix` option, or the prefix chosen when asked.
     *
     * @param  bool  $offered
     * @return ?string
     */
    private function tablePrefix(bool $offered): ?string
    {
        $option = $this->option('prefix');

        if (is_string($option)) {
            return $option !== '' ? $option : null;
        }

        if (!$offered || !$this->confirm(self::PREFIX_QUESTION)) {
            return null;
        }

        $prefix = $this->ask('Table prefix', 'authorization_');

        return is_string($prefix) ? $prefix : null;
    }

    /**
     * Write the prefix into the newly published authorization config, or say
     * why not.
     *
     * @param  \Illuminate\Filesystem\Filesystem  $files
     * @param  ?string  $configuration
     * @param  string  $prefix
     * @return void
     *
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    private function prefixTables(Filesystem $files, ?string $configuration, string $prefix): void
    {
        if ($configuration === null && TableNames::prefix() === $prefix) {
            $this->info("laravel-authorization's tables already carry the prefix `{$prefix}`.");

            return;
        }

        if ($configuration === null) {
            $this->warn('laravel-authorization\'s tables keep their names: its configuration or its migrations were published before.');

            return;
        }

        $contents = str_replace('env(\'AUTHORIZATION_TABLE_PREFIX\', \'\')', "env('AUTHORIZATION_TABLE_PREFIX', '{$prefix}')", $files->get($configuration), $count);

        if ($count === 0) {
            $this->warn('Set `authorization.tables.prefix` yourself: laravel-authorization\'s configuration does not declare it.');

            return;
        }

        $files->put($configuration, $contents);

        $this->info("Prefixed laravel-authorization's tables with `{$prefix}`.");
    }

    /**
     * Where authorization's config is published while none of its files is yet.
     *
     * @param  \Illuminate\Filesystem\Filesystem  $files
     * @param  \SineMacula\Laravel\Iam\Install\MigrationLedger  $ledger
     * @return ?string
     *
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    private function prefixableConfiguration(Filesystem $files, MigrationLedger $ledger): ?string
    {
        $configuration = self::pathsOf('authorization-config')[0] ?? null;
        $migrations    = self::migrationsOf($files, 'authorization-migrations');

        if ($configuration === null || $migrations === [] || $files->exists($configuration)) {
            return null;
        }

        foreach ($migrations as $destination) {

            if ($ledger->copyOf($destination, self::MIGRATIONS['authorization-migrations']) !== null) {
                return null;
            }
        }

        return $configuration;
    }

    /**
     * Every migration a tag publishes, by source, with its destination.
     *
     * @param  \Illuminate\Filesystem\Filesystem  $files
     * @param  string  $tag
     * @return array<string, string>
     */
    private static function migrationsOf(Filesystem $files, string $tag): array
    {
        $migrations = [];

        /** @var array<string, string> $paths */
        $paths = ServiceProvider::pathsToPublish(null, $tag);

        foreach ($paths as $source => $destination) {

            if (!$files->isDirectory($source)) {
                $migrations[$source] = $destination;

                continue;
            }

            foreach ($files->files($source) as $file) {
                $migrations[$file->getPathname()] = $destination . '/' . $file->getFilename();
            }
        }

        return $migrations;
    }

    /**
     * Where a tag publishes its files.
     *
     * @param  string  $tag
     * @return list<string>
     */
    private static function pathsOf(string $tag): array
    {
        /** @var array<string, string> $paths */
        $paths = ServiceProvider::pathsToPublish(null, $tag);

        return array_values($paths);
    }
}
