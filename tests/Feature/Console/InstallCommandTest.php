<?php

declare(strict_types = 1);

namespace Tests\Feature\Console;

use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\ServiceProvider;
use Illuminate\Testing\PendingCommand;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\AuditLogServiceProvider;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Iam\Console\InstallCommand;
use SineMacula\Laravel\Mfa\MfaServiceProvider;
use SineMacula\Laravel\Sso\SsoServiceProvider;
use Tests\Concerns\NamesAuthorizationTables;
use Tests\Concerns\UsesScratchDirectory;
use Tests\TestCase;

/**
 * Feature tests for `iam:install` (IAM-2.1, IAM-2.4).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(InstallCommand::class)]
final class InstallCommandTest extends TestCase
{
    use NamesAuthorizationTables, UsesScratchDirectory;

    /** @var array<string, class-string<\Illuminate\Support\ServiceProvider>> Each member's configuration key and the provider that ships its files. */
    private const array MEMBERS = [
        'authentication' => AuthenticationServiceProvider::class,
        'authorization'  => AuthorizationServiceProvider::class,
        'mfa'            => MfaServiceProvider::class,
        'sso'            => SsoServiceProvider::class,
        'audit-log'      => AuditLogServiceProvider::class,
    ];

    /** @var string The question whether to prefix `laravel-authorization`'s tables. */
    private const string QUESTION = 'Prefix laravel-authorization\'s tables (roles, permissions, policies and the grant tables), whose names may collide with your own?';

    /** @var ?array<string, array<string, string>> The publishing groups before a test replaced one, restored once it ends. */
    private ?array $publishGroups = null;

    /**
     * Restore the publishing groups a test replaced, then delete the test's
     * directory.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        if ($this->publishGroups !== null) {
            (new \ReflectionProperty(ServiceProvider::class, 'publishGroups'))->setValue(null, $this->publishGroups);
        }

        parent::tearDown();

        $this->deleteScratch();
    }

    /**
     * Every member's configuration, language files and migrations, and this
     * package's configuration, are published.
     *
     * @return void
     */
    public function testEveryMembersFilesArePublished(): void
    {
        [$code, $output] = $this->install();

        self::assertSame(0, $code, $output);

        foreach (self::MEMBERS as $key => $provider) {
            $package = self::packagePath($provider);

            self::assertFileEquals($package . "/config/{$key}.php", $this->scratch("config/{$key}.php"));

            foreach (glob($package . '/database/migrations/*.php') ?: [] as $migration) {
                self::assertFileEquals($migration, $this->scratch('database/migrations/' . basename($migration)));
                self::assertStringContainsString('Published ' . basename($migration) . ".\n", $output);
            }

            foreach (is_dir($package . '/lang') ? (new Filesystem)->allFiles($package . '/lang') : [] as $file) {
                self::assertFileEquals($file->getPathname(), $this->scratch("lang/vendor/{$key}/" . $file->getRelativePathname()));
            }
        }

        self::assertFileEquals(dirname(__DIR__, 3) . '/config/iam.php', $this->scratch('config/iam.php'));
        self::assertDirectoryDoesNotExist($this->scratch('lang/vendor/authentication'));
        self::assertCount(self::migrationCount(), glob($this->scratch('database/migrations/*.php')) ?: []);
    }

    /**
     * Run twice, the second run publishes nothing and changes no file.
     *
     * @return void
     */
    public function testRunningTwiceChangesNothing(): void
    {
        $this->install();

        $before = $this->snapshot();

        [$code, $output] = $this->install();

        self::assertSame(0, $code);
        self::assertSame($before, $this->snapshot());
        self::assertStringNotContainsString('Published ', $output);
        self::assertSame(self::migrationCount(), substr_count($output, 'Kept '));
    }

    /**
     * A member's migration already published under another timestamp is
     * recognised and never published again.
     *
     * @return void
     */
    public function testAMigrationPublishedUnderAnotherTimestampIsRecognised(): void
    {
        $source = self::packagePath(MfaServiceProvider::class) . '/database/migrations/2026_04_15_000000_create_mfa_factors_table.php';
        $copy   = $this->writeScratch('database/migrations/2025_01_01_120000_create_mfa_factors_table.php', (string) file_get_contents($source));

        [$code, $output] = $this->install();

        self::assertSame(0, $code);
        self::assertFileDoesNotExist($this->scratch('database/migrations/2026_04_15_000000_create_mfa_factors_table.php'));
        self::assertFileEquals($source, $copy);
        self::assertStringContainsString('Kept 2026_04_15_000000_create_mfa_factors_table.php, published as 2025_01_01_120000_create_mfa_factors_table.php.', $output);
        self::assertCount(self::migrationCount(), glob($this->scratch('database/migrations/*.php')) ?: []);
    }

    /**
     * An application's own migration sharing a member's base name is not taken
     * for the member's.
     *
     * @return void
     */
    public function testAnApplicationsMigrationSharingABaseNameIsNotTakenForTheMembers(): void
    {
        $contents = "<?php\n\n// The application's own roles table\n";
        $own      = $this->writeScratch('database/migrations/2019_01_01_000000_create_roles_table.php', $contents);

        [$code] = $this->install();

        self::assertSame(0, $code);
        self::assertStringEqualsFile($own, $contents);
        self::assertFileExists($this->scratch('database/migrations/2026_04_14_000001_create_roles_table.php'));
    }

    /**
     * A file of the application's at the very path a member's migration is
     * published to is never overwritten.
     *
     * @return void
     */
    public function testAFileAtAMigrationsPathIsNeverOverwritten(): void
    {
        $contents = "<?php\n\n// The application's own file\n";
        $own      = $this->writeScratch('database/migrations/2026_04_15_000000_create_mfa_factors_table.php', $contents);

        [$code, $output] = $this->install();

        self::assertSame(0, $code);
        self::assertStringEqualsFile($own, $contents);
        self::assertStringContainsString('Kept 2026_04_15_000000_create_mfa_factors_table.php, published as 2026_04_15_000000_create_mfa_factors_table.php.', $output);
    }

    /**
     * An existing configuration file and an existing language file are left as
     * they are.
     *
     * @return void
     */
    public function testAnExistingConfigurationFileIsKept(): void
    {
        $configuration = $this->writeScratch('config/mfa.php', "<?php\n\nreturn ['kept' => true];\n");
        $language      = $this->writeScratch('lang/vendor/sso/en/messages.php', "<?php\n\nreturn [];\n");

        [$code] = $this->install();

        self::assertSame(0, $code);
        self::assertStringEqualsFile($configuration, "<?php\n\nreturn ['kept' => true];\n");
        self::assertStringEqualsFile($language, "<?php\n\nreturn [];\n");
        self::assertFileExists($this->scratch('config/sso.php'));
    }

    /**
     * Every run ends with what the application still owes, each item pointing
     * at the installation guide.
     *
     * @return void
     */
    public function testTheRunEndsWithWhatTheApplicationStillOwes(): void
    {
        [, $output] = $this->install();

        $guide = InstallCommand::GUIDE;

        self::assertStringEndsWith(
            "\n\nStill to do:\n"
            . " - Run `php artisan migrate`: {$guide}#the-storage-connection\n"
            . " - Add every `jwt` and `api_key` guard to `audit-log.capture.laravel.except_guards`: {$guide}#the-audit-log-configuration\n"
            . " - Turn `audit-log.definitions.require_registered` on: {$guide}#the-audit-log-configuration\n"
            . " - Declare MFA's and SSO's freshness operations for their guards: {$guide}#guards-and-applications\n"
            . " - Bind the contracts the package leaves to you, and add the routes: {$guide}#what-you-still-owe\n"
            . " - Call `Iam::schedule()`, and run the scheduler and a queue worker: {$guide}#what-you-still-owe\n"
            . " - Run `php artisan iam:check` on every deploy: {$guide}#checking\n",
            $output,
        );
    }

    /**
     * A tag no provider registered is reported and fails the run, and the rest
     * is still published.
     *
     * @return void
     */
    public function testATagNoProviderRegisteredFailsTheRun(): void
    {
        $this->replacePublication('sso-lang', null);
        $this->replacePublication('mfa-migrations', null);

        [$code, $output] = $this->install();

        self::assertSame(1, $code);
        self::assertStringContainsString('No provider registered the `sso-lang` tag.', $output);
        self::assertStringContainsString('No provider registered the `mfa-migrations` tag.', $output);
        self::assertDirectoryDoesNotExist($this->scratch('lang/vendor/sso'));
        self::assertFileDoesNotExist($this->scratch('database/migrations/2026_04_15_000000_create_mfa_factors_table.php'));
        self::assertFileExists($this->scratch('config/iam.php'));
    }

    /**
     * `--prefix` prefixes every `laravel-authorization` table in its
     * configuration published in the run.
     *
     * @return void
     */
    public function testThePrefixOptionPrefixesTheAuthorizationTables(): void
    {
        [$code, $output] = $this->install(['--prefix' => 'authz_']);

        self::assertSame(0, $code);
        self::assertSame(self::prefixedAuthorizationTables('authz_'), $this->authorizationTables());
        self::assertStringContainsString('Prefixed laravel-authorization\'s tables with `authz_`.', $output);
    }

    /**
     * Run again, the same prefix is noted as carried and another one is not
     * written.
     *
     * @return void
     */
    public function testRunningAgainWithAPrefixWritesNothing(): void
    {
        $this->install(['--prefix' => 'authz_']);

        $before = $this->snapshot();

        [$code, $output] = $this->install(['--prefix' => 'authz_']);

        self::assertSame(0, $code);
        self::assertSame($before, $this->snapshot());
        self::assertStringContainsString('laravel-authorization\'s tables already carry the prefix `authz_`.', $output);

        [$code, $output] = $this->install(['--prefix' => 'other_']);

        self::assertSame(0, $code);
        self::assertSame($before, $this->snapshot());
        self::assertStringContainsString('laravel-authorization\'s tables keep their names: its configuration or its migrations were published before.', $output);
    }

    /**
     * A prefix is not written into a configuration already published.
     *
     * @return void
     */
    public function testAPrefixIsNotWrittenIntoAConfigurationAlreadyPublished(): void
    {
        $file = $this->writeScratch('config/authorization.php', "<?php\n\nreturn [];\n");

        [$code, $output] = $this->install(['--prefix' => 'authz_']);

        self::assertSame(0, $code);
        self::assertStringEqualsFile($file, "<?php\n\nreturn [];\n");
        self::assertStringContainsString('laravel-authorization\'s tables keep their names', $output);
    }

    /**
     * A prefix is not written once one of `laravel-authorization`'s migrations
     * is published, under any timestamp.
     *
     * @return void
     */
    public function testAPrefixIsNotWrittenOnceAnAuthorizationMigrationIsPublished(): void
    {
        $source = self::packagePath(AuthorizationServiceProvider::class) . '/database/migrations/2026_04_14_000010_create_guardrails_table.php';

        $this->writeScratch('database/migrations/2024_01_01_000000_create_guardrails_table.php', (string) file_get_contents($source));

        [$code, $output] = $this->install(['--prefix' => 'authz_']);

        self::assertSame(0, $code);
        self::assertSame('roles', $this->authorizationTables()['roles']);
        self::assertStringContainsString('laravel-authorization\'s tables keep their names', $output);
    }

    /**
     * A prefix is not written while either of `laravel-authorization`'s tags is
     * unregistered.
     *
     * @return void
     */
    public function testAPrefixIsNotWrittenWhileATagIsUnregistered(): void
    {
        $this->replacePublication('authorization-migrations', null);

        [$code, $output] = $this->install(['--prefix' => 'authz_']);

        self::assertSame(1, $code);
        self::assertSame('roles', $this->authorizationTables()['roles']);
        self::assertStringContainsString('laravel-authorization\'s tables keep their names', $output);

        $this->deleteScratch();
        $this->restorePublications();
        $this->replacePublication('authorization-config', null);

        [$code, $output] = $this->install(['--prefix' => 'authz_']);

        self::assertSame(1, $code);
        self::assertStringContainsString('laravel-authorization\'s tables keep their names', $output);
    }

    /**
     * A configuration published in the run that no longer holds the table name
     * defaults is owed the prefix.
     *
     * @return void
     */
    public function testAReshapedAuthorizationConfigurationIsOwedThePrefix(): void
    {
        $this->replacePublication('authorization-config', [dirname(__DIR__, 2) . '/Fixtures/Install/reshaped-authorization.php' => $this->scratch('config/authorization.php')]);

        [$code, $output] = $this->install(['--prefix' => 'authz_']);

        self::assertSame(0, $code);
        self::assertStringContainsString(
            'Prefix laravel-authorization\'s tables yourself (`authorization.tables`): its configuration no longer holds their defaults.',
            $output,
        );
    }

    /**
     * An invalid prefix refuses the run before anything is published.
     *
     * @return void
     */
    public function testAnInvalidPrefixRefusesTheRunWithNothingPublished(): void
    {
        [$code, $output] = $this->install(['--prefix' => 'Authz-']);

        self::assertSame(2, $code);
        self::assertStringContainsString('The table prefix must be lower-case letters', $output);
        self::assertSame([], $this->snapshot());
    }

    /**
     * Interactive, the run asks for the prefix, and prefixes the tables with
     * the one given.
     *
     * @return void
     */
    public function testInteractiveTheRunAsksForThePrefix(): void
    {
        $this->interactively()
            ->expectsConfirmation(self::QUESTION, 'yes')
            ->expectsQuestion('Table prefix', 'iam_')
            ->assertExitCode(0)
            ->run();

        self::assertSame('iam_roles', $this->authorizationTables()['roles']);
    }

    /**
     * Interactive, declining the prefix leaves the tables' own names.
     *
     * @return void
     */
    public function testInteractiveDecliningThePrefixLeavesTheNames(): void
    {
        $this->interactively()
            ->expectsConfirmation(self::QUESTION, 'no')
            ->assertExitCode(0)
            ->run();

        self::assertSame('roles', $this->authorizationTables()['roles']);
    }

    /**
     * Interactive, nothing is asked when `--prefix` gives the prefix, or once
     * it can no longer be written.
     *
     * @return void
     */
    public function testInteractiveNothingIsAskedWhenThePrefixIsGivenOrCannotBeWritten(): void
    {
        $this->interactively(['--prefix' => ''])->assertExitCode(0)->run();

        self::assertSame('roles', $this->authorizationTables()['roles']);

        $this->interactively()->assertExitCode(0)->run();
    }

    /**
     * Point the application's configuration, database and language directories
     * at the test's own.
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

    /**
     * Run `iam:install` without interaction, and return its exit code and its
     * output.
     *
     * @param  array<string, mixed>  $options
     * @return array{int, string}
     */
    private function install(array $options = []): array
    {
        $code = Artisan::call(InstallCommand::NAME, ['--no-interaction' => true, ...$options]);

        return [$code, Artisan::output()];
    }

    /**
     * Run `iam:install` interactively, its questions answered as the test
     * expects.
     *
     * @param  array<string, mixed>  $options
     * @return \Illuminate\Testing\PendingCommand
     */
    private function interactively(array $options = []): PendingCommand
    {
        $command = $this->artisan(InstallCommand::NAME, $options);

        self::assertInstanceOf(PendingCommand::class, $command);

        return $command;
    }

    /**
     * The table names `laravel-authorization`'s published configuration holds.
     *
     * @return array<string, string>
     */
    private function authorizationTables(): array
    {
        /** @var array{tables: array<string, string>} $configuration */
        $configuration = require $this->scratch('config/authorization.php');

        return $configuration['tables'];
    }

    /**
     * Replace the paths a publishing tag holds, or remove the tag, until the
     * test ends.
     *
     * @param  string  $tag
     * @param  ?array<string, string>  $paths
     * @return void
     */
    private function replacePublication(string $tag, ?array $paths): void
    {
        $property = new \ReflectionProperty(ServiceProvider::class, 'publishGroups');

        /** @var array<string, array<string, string>> $groups */
        $groups = $property->getValue();

        $this->publishGroups ??= $groups;

        if ($paths === null) {
            unset($groups[$tag]);
        } else {
            $groups[$tag] = $paths;
        }

        $property->setValue(null, $groups);
    }

    /**
     * Restore the publishing groups a test replaced.
     *
     * @return void
     */
    private function restorePublications(): void
    {
        (new \ReflectionProperty(ServiceProvider::class, 'publishGroups'))->setValue(null, $this->publishGroups);
    }

    /**
     * Every file in the test's directory with a hash of its contents.
     *
     * @return array<string, string>
     */
    private function snapshot(): array
    {
        $files = [];

        if (!is_dir($this->scratch())) {
            return [];
        }

        foreach ((new Filesystem)->allFiles($this->scratch()) as $file) {
            $files[$file->getRelativePathname()] = hash_file('sha256', $file->getPathname()) . '@' . $file->getMTime();
        }

        ksort($files);

        return $files;
    }

    /**
     * The root of the package a provider ships.
     *
     * @param  class-string<\Illuminate\Support\ServiceProvider>  $provider
     * @return string
     */
    private static function packagePath(string $provider): string
    {
        return dirname((string) (new \ReflectionClass($provider))->getFileName(), 2);
    }

    /**
     * The number of migrations the members ship between them.
     *
     * @return int
     */
    private static function migrationCount(): int
    {
        return array_sum(array_map(static fn (string $provider): int => count(glob(self::packagePath($provider) . '/database/migrations/*.php') ?: []), self::MEMBERS));
    }
}
