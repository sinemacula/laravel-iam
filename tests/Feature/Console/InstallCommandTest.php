<?php

declare(strict_types = 1);

namespace Tests\Feature\Console;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\ServiceProvider;
use Illuminate\Testing\PendingCommand;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\AuditLogServiceProvider;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Iam\Audit\AuditSettings;
use SineMacula\Laravel\Iam\Audit\CaptureExclusions;
use SineMacula\Laravel\Iam\Console\InstallCommand;
use SineMacula\Laravel\Iam\Exceptions\PublicationFailedException;
use SineMacula\Laravel\Iam\Install\Installer;
use SineMacula\Laravel\Iam\Install\InstallReport;
use SineMacula\Laravel\Mfa\MfaServiceProvider;
use SineMacula\Laravel\Sso\SsoServiceProvider;
use Tests\Concerns\UsesScratchDirectory;
use Tests\TestCase;

/**
 * Feature tests for `iam:install` (IAM-2.1, IAM-2.4): every member's
 * configuration, language files and migrations, and this package's
 * configuration, published in their working order; safe to run twice; a
 * migration already published under another timestamp recognised by its base
 * name and never published again; an existing configuration file kept;
 * audit-log's values written into the configuration published (decision Q5
 * (a)); prefixed authorization table names offered; and what the application
 * still owes reported.
 *
 * The application's configuration, database and language directories are a
 * directory of each test's own, set before any provider registers, so every
 * member's tags publish there.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(InstallCommand::class)]
#[CoversClass(Installer::class)]
#[CoversClass(InstallReport::class)]
#[CoversClass(PublicationFailedException::class)]
final class InstallCommandTest extends TestCase
{
    use UsesScratchDirectory;

    /** @var array<string, class-string<\Illuminate\Support\ServiceProvider>> Each member's configuration key and the provider that ships its files. */
    private const array MEMBERS = [
        'authentication' => AuthenticationServiceProvider::class,
        'authorization'  => AuthorizationServiceProvider::class,
        'mfa'            => MfaServiceProvider::class,
        'sso'            => SsoServiceProvider::class,
        'audit-log'      => AuditLogServiceProvider::class,
    ];

    /** @var ?array<string, array<string, string>> The publishing groups before a test replaced one, restored once it ends. */
    private ?array $publishGroups = null;

    /** @var list<string> The directories a test made read-only, made writable again once it ends. */
    private array $readOnly = [];

    /**
     * Restore the publishing groups a test replaced, destroy the application,
     * then make every directory the test made read-only writable again and
     * delete the test's directory.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach ($this->readOnly as $directory) {
            chmod($directory, 0755);
        }

        if ($this->publishGroups !== null) {
            (new \ReflectionProperty(ServiceProvider::class, 'publishGroups'))->setValue(null, $this->publishGroups);
        }

        parent::tearDown();

        $this->deleteScratch();
    }

    /**
     * Every member's configuration, language files and migrations, and this
     * package's configuration, are published, in their working order, each as
     * its member ships it, and the run succeeds.
     *
     * @return void
     */
    public function testEveryMembersFilesArePublishedInTheirWorkingOrder(): void
    {
        [$code, $output] = $this->install();

        self::assertSame(0, $code);

        foreach (self::MEMBERS as $key => $provider) {
            $package = self::packagePath($provider);

            self::assertFileExists($this->scratch("config/{$key}.php"));

            foreach (glob($package . '/database/migrations/*.php') ?: [] as $migration) {
                self::assertFileEquals($migration, $this->scratch('database/migrations/' . basename($migration)));
            }

            foreach (is_dir($package . '/lang') ? (new Filesystem)->allFiles($package . '/lang') : [] as $file) {
                self::assertFileEquals($file->getPathname(), $this->scratch("lang/vendor/{$key}/" . $file->getRelativePathname()));
            }
        }

        self::assertFileEquals(dirname(__DIR__, 3) . '/config/iam.php', $this->scratch('config/iam.php'));
        self::assertDirectoryDoesNotExist($this->scratch('lang/vendor/authentication'));
        self::assertCount(50, glob($this->scratch('database/migrations/*.php')) ?: []);

        preg_match_all('/^\[published\] .*?(config\/[\w-]+\.php|lang\/vendor\/[\w-]+|database\/migrations)/m', $output, $matches);

        self::assertSame([
            'config/authentication.php',
            'database/migrations',
            'config/authorization.php',
            'lang/vendor/authorization',
            'database/migrations',
            'config/mfa.php',
            'lang/vendor/mfa',
            'database/migrations',
            'config/sso.php',
            'lang/vendor/sso',
            'database/migrations',
            'config/audit-log.php',
            'lang/vendor/audit-log',
            'database/migrations',
            'config/iam.php',
        ], self::collapse($matches[1]));
    }

    /**
     * Run twice, the second run publishes nothing and changes no file, and
     * reports each file kept or recognised.
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
        self::assertStringNotContainsString('[published]', $output);
        self::assertStringNotContainsString('[written]', $output);
        self::assertSame(50, substr_count($output, '[recognised]'));
        self::assertStringContainsString('[kept] ' . $this->scratch('config/audit-log.php'), $output);
        self::assertStringContainsString('[kept] ' . $this->scratch('lang/vendor/mfa/en/messages.php'), $output);
    }

    /**
     * A member's migration already published under another timestamp is
     * recognised by its base name and never published a second time.
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
        self::assertStringContainsString('[recognised] 2026_04_15_000000_create_mfa_factors_table.php, published as ' . $copy, $output);
        self::assertCount(50, glob($this->scratch('database/migrations/*.php')) ?: []);
    }

    /**
     * An application's own migration that shares a member's base name is not
     * taken for the member's: the member's is published beside it, the
     * application's is left as it is, and the run that finds it fails as a
     * conflict; a later run recognises the member's copy and passes.
     *
     * @return void
     */
    public function testAnApplicationsMigrationSharingABaseNameIsNotTakenForTheMembers(): void
    {
        $contents = "<?php\n\n// The application's own roles table\n";
        $own      = $this->writeScratch('database/migrations/2019_01_01_000000_create_roles_table.php', $contents);

        [$code, $output] = $this->install();

        self::assertSame(1, $code);
        self::assertStringEqualsFile($own, $contents);
        self::assertFileExists($this->scratch('database/migrations/2026_04_14_000001_create_roles_table.php'));
        self::assertStringContainsString(
            '[conflict] 2019_01_01_000000_create_roles_table.php shares its base name with 2026_04_14_000001_create_roles_table.php, published beside it',
            $output,
        );

        [$code, $output] = $this->install();

        self::assertSame(0, $code);
        self::assertStringNotContainsString('[conflict]', $output);
        self::assertStringEqualsFile($own, $contents);
    }

    /**
     * A file of the application's at the very path a member's migration is
     * published to is never overwritten, and fails every run until it is moved,
     * the member's migration left unpublished meanwhile.
     *
     * @return void
     */
    public function testAFileAtAMigrationsPathIsNeverOverwritten(): void
    {
        $contents = "<?php\n\n// The application's own file\n";
        $own      = $this->writeScratch('database/migrations/2026_04_15_000000_create_mfa_factors_table.php', $contents);

        foreach ([1, 2] as $run) {
            [$code, $output] = $this->install();

            self::assertSame(1, $code, "Run {$run}");
            self::assertStringEqualsFile($own, $contents);
            self::assertStringContainsString(
                '[conflict] 2026_04_15_000000_create_mfa_factors_table.php is where mfa-migrations publishes its migration, but is not its copy',
                $output,
            );
            self::assertStringNotContainsString('shares its base name', $output);
            self::assertCount(50, glob($this->scratch('database/migrations/*.php')) ?: []);
        }

        unlink($own);

        [$code] = $this->install();

        self::assertSame(0, $code);
        self::assertStringNotEqualsFile($own, $contents);
    }

    /**
     * A path under the application's base path is reported relative to it.
     *
     * @return void
     */
    public function testAPathUnderTheBasePathIsReportedRelativeToIt(): void
    {
        $this->app?->setBasePath($this->scratch());

        [$code, $output] = $this->install();

        self::assertSame(0, $code);
        self::assertStringContainsString("[published] config/authentication.php\n", $output);
        self::assertStringContainsString("[published] lang/vendor/mfa/en/messages.php\n", $output);
    }

    /**
     * An existing configuration file and an existing language file are left as
     * they are, and every other file is still published.
     *
     * @return void
     */
    public function testAnExistingConfigurationFileIsKept(): void
    {
        $configuration = $this->writeScratch('config/mfa.php', "<?php\n\nreturn ['kept' => true];\n");
        $language      = $this->writeScratch('lang/vendor/sso/en/messages.php', "<?php\n\nreturn [];\n");

        [$code, $output] = $this->install();

        self::assertSame(0, $code);
        self::assertStringEqualsFile($configuration, "<?php\n\nreturn ['kept' => true];\n");
        self::assertStringEqualsFile($language, "<?php\n\nreturn [];\n");
        self::assertStringContainsString('[kept] ' . $configuration, $output);
        self::assertStringContainsString('[kept] ' . $language, $output);
        self::assertFileExists($this->scratch('config/sso.php'));
    }

    /**
     * Audit-log's configuration, published in the run, holds every `jwt` and
     * `api_key` guard excluded and the refusal of unregistered codes on, with
     * Gate capture left off, and nothing is owed for them.
     *
     * @return void
     */
    public function testTheAuditLogValuesAreWrittenIntoItsConfigurationPublished(): void
    {
        [$code, $output] = $this->install();

        self::assertSame(0, $code);

        /** @var array{capture: array{laravel: array{except_guards: list<string>}, gate: array{enabled: mixed}}, definitions: array{require_registered: mixed}} $configuration */
        $configuration = require $this->scratch('config/audit-log.php');

        self::assertSame(['api', 'keys'], $configuration['capture']['laravel']['except_guards']);
        self::assertTrue($configuration['definitions']['require_registered']);
        self::assertFalse($configuration['capture']['gate']['enabled']);
        self::assertStringContainsString('[written] audit-log.capture.laravel.except_guards: [\'api\', \'keys\']', $output);
        self::assertStringContainsString('[written] audit-log.definitions.require_registered: true', $output);
        self::assertStringNotContainsString(' to `audit-log.capture.laravel.except_guards`', $output);
        self::assertStringNotContainsString('Turn `audit-log.definitions.require_registered` on', $output);
        self::assertStringNotContainsString('Gate capture off', $output);
    }

    /**
     * With no guard of either driver, nothing is written for the exclusions and
     * nothing is owed for them.
     *
     * @return void
     */
    public function testNoGuardToExcludeWritesNoExclusions(): void
    {
        $this->config()->set('auth.guards', ['web' => ['driver' => 'session', 'provider' => 'people']]);

        [$code, $output] = $this->install();

        self::assertSame(0, $code);
        self::assertStringNotContainsString('[written] audit-log.capture.laravel.except_guards', $output);
        self::assertStringNotContainsString(' to `audit-log.capture.laravel.except_guards`', $output);
        self::assertStringContainsString('[written] audit-log.definitions.require_registered: true', $output);
    }

    /**
     * Audit-log's configuration already published is left alone, and each value
     * it does not hold is owed instead, as is Gate capture while it is on.
     *
     * @return void
     */
    public function testTheAuditLogValuesAreOwedWhenItsConfigurationIsKept(): void
    {
        $file = $this->writeScratch('config/audit-log.php', "<?php\n\nreturn [];\n");

        $this->config()->set(CaptureExclusions::EXCEPT_GUARDS_KEY, ['api']);
        $this->config()->set(CaptureExclusions::GATE_KEY, true);

        [$code, $output] = $this->install();

        self::assertSame(0, $code);
        self::assertStringEqualsFile($file, "<?php\n\nreturn [];\n");
        self::assertStringNotContainsString('[written] audit-log', $output);
        self::assertStringContainsString(' - Add [\'keys\'] to `audit-log.capture.laravel.except_guards`, so nothing the suite records is recorded twice.', $output);
        self::assertStringContainsString(
            ' - Turn `audit-log.definitions.require_registered` on (`true`), so a code no definition registers is refused rather than recorded unchecked.',
            $output,
        );
        self::assertStringContainsString(' - Turn audit-log\'s Gate capture off (`audit-log.capture.gate.enabled`)', $output);
    }

    /**
     * Audit-log's configuration already published that holds every value is
     * owed nothing.
     *
     * @return void
     */
    public function testNothingIsOwedForAuditLogsConfigurationThatHolds(): void
    {
        $this->writeScratch('config/audit-log.php', "<?php\n\nreturn [];\n");

        $this->config()->set(CaptureExclusions::EXCEPT_GUARDS_KEY, ['*']);
        $this->config()->set(AuditSettings::REQUIRE_REGISTERED, true);

        [$code, $output] = $this->install();

        self::assertSame(0, $code);
        self::assertStringNotContainsString(' to `audit-log.capture.laravel.except_guards`', $output);
        self::assertStringNotContainsString('Turn `audit-log.definitions.require_registered` on', $output);
    }

    /**
     * An audit-log configuration published in the run that no longer holds
     * audit-log's defaults is written nothing, and each value is owed.
     *
     * @return void
     */
    public function testAReshapedAuditLogConfigurationIsOwedItsValues(): void
    {
        $this->replacePublication('audit-log-config', [dirname(__DIR__, 2) . '/Fixtures/Install/reshaped-audit-log.php' => $this->scratch('config/audit-log.php')]);

        [$code, $output] = $this->install();

        self::assertSame(0, $code);
        self::assertStringNotContainsString('[written] audit-log', $output);
        self::assertStringContainsString(' - Add [\'api\', \'keys\'] to `audit-log.capture.laravel.except_guards`', $output);
        self::assertStringContainsString(' - Turn `audit-log.definitions.require_registered` on (`true`)', $output);
    }

    /**
     * A malformed exclusion list refuses the run before anything is published.
     *
     * @return void
     */
    public function testAMalformedExclusionListRefusesTheRunWithNothingPublished(): void
    {
        $this->config()->set(CaptureExclusions::EXCEPT_GUARDS_KEY, 'api');

        [$code, $output] = $this->install();

        self::assertSame(2, $code);
        self::assertStringContainsString('`audit-log.capture.laravel.except_guards` must be a list of guard names', $output);
        self::assertSame([], $this->snapshot());
    }

    /**
     * Every run ends with what the application still owes.
     *
     * @return void
     */
    public function testTheRunEndsWithWhatTheApplicationStillOwes(): void
    {
        [, $output] = $this->install();

        self::assertStringContainsString("\n\nStill to do:\n", $output);

        $owed = substr($output, (int) strpos($output, 'Still to do:'));

        foreach (Installer::OWED as $item) {
            self::assertStringContainsString(' - ' . $item, $owed);
        }

        self::assertStringContainsString('iam.delivery.email', $owed);
        self::assertStringContainsString('iam.tenancy', $owed);
        self::assertStringContainsString('Bind laravel-authentication\'s `TenantResolver`', $owed);
        self::assertStringContainsString('even if your principals act only in their own tenant', $owed);
        self::assertStringContainsString('iam.provisioning.provisioner', $owed);
        self::assertStringContainsString('routes', $owed);
        self::assertStringContainsString('laravel-iam\'s example application guide (docs/guides/example-application.md)', $owed);
        self::assertStringContainsString('redeem SSO\'s handoffs through `Iam::signIns()`, `Iam::reauthentications()` and `Iam::links()`', $owed);
        self::assertStringContainsString('never `HandoffRedemption` directly', $owed);
        self::assertStringNotContainsString('laravel-sso\'s example application guide', $owed);
        self::assertStringContainsString('`AuditLog::define()`', $owed);
        self::assertStringContainsString('`audit-log.definitions.require_registered`', $owed);
        self::assertStringContainsString('Iam::schedule', $owed);
        self::assertStringContainsString('`ApplicationAccess`, `TenantAccess`, `ScopeRegistry`', $owed);
        self::assertStringContainsString('authentication.freshness', $owed);
        self::assertStringContainsString('external_provider', $owed);
    }

    /**
     * The worker item asks for a queue worker for `laravel-authentication`'s
     * delivery of every one-time code, MFA's email and SMS codes among them,
     * whether or not SSO is in use, and for SSO's metadata refresh while it is.
     *
     * @return void
     */
    public function testTheWorkerItemAsksForAWorkerThatDeliversEveryCode(): void
    {
        [, $output] = $this->install();

        $owed = substr($output, (int) strpos($output, 'Still to do:'));

        self::assertStringContainsString(
            ' - Run a queue worker for laravel-authentication\'s delivery of one-time codes (`authentication.delivery.queue.connection`'
                . ' and `authentication.delivery.queue.name`), which laravel-mfa\'s email and SMS codes go through once the gateways are named,'
                . ' and, while laravel-sso is in use, for its metadata refresh (`sso.metadata.queue`):'
                . ' see laravel-iam\'s operations guide (docs/guides/operations.md#queues).',
            $owed,
        );
        self::assertStringNotContainsString('and run a queue worker for laravel-sso\'s metadata refresh', $owed);
    }

    /**
     * The migration item names the connection each member's tables are created
     * on: `laravel-authentication`'s, MFA's and SSO's on the shared one,
     * audit-log's and `laravel-authorization`'s on their own keys, which the
     * alignment never writes.
     *
     * @return void
     */
    public function testTheMigrationItemNamesEachMembersConnection(): void
    {
        [, $output] = $this->install();

        $owed = substr($output, (int) strpos($output, 'Still to do:'));

        self::assertStringContainsString(
            ' - Run `php artisan migrate`: laravel-authentication\'s, laravel-mfa\'s and laravel-sso\'s tables are created on'
                . ' `iam.storage.connection`, laravel-audit-log\'s on `audit-log.storage.connection` and laravel-authorization\'s'
                . ' on `authorization.connection`, each the default connection when unset.',
            $owed,
        );
        self::assertStringNotContainsString('every member\'s tables', $owed);
    }

    /**
     * A tag no provider registered is reported, the rest is still published,
     * and the run fails.
     *
     * @return void
     */
    public function testATagNoProviderRegisteredFailsTheRun(): void
    {
        $this->replacePublication('mfa-lang', null);

        [$code, $output] = $this->install();

        self::assertSame(1, $code);
        self::assertStringContainsString('[missing] No provider registered the `mfa-lang` tag; nothing was published for it.', $output);
        self::assertDirectoryDoesNotExist($this->scratch('lang/vendor/mfa'));
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

        /** @var array{tables: array<string, string>} $configuration */
        $configuration = require $this->scratch('config/authorization.php');

        self::assertCount(10, $configuration['tables']);

        foreach ($configuration['tables'] as $key => $table) {
            self::assertSame('authz_' . $key, $table);
            self::assertStringContainsString("[written] authorization.tables.{$key}: authz_{$key}", $output);
        }
    }

    /**
     * Run twice with the same prefix, the second run writes nothing, owes no
     * prefix, and notes that the tables already carry it; a different prefix
     * given then, the start of the first one among them, is owed, the tables
     * keeping the names the first run wrote.
     *
     * @return void
     */
    public function testRunningTwiceWithThePrefixOwesNothing(): void
    {
        $this->install(['--prefix' => 'authz_']);

        $before = $this->snapshot();

        [$code, $output] = $this->install(['--prefix' => 'authz_']);

        self::assertSame(0, $code);
        self::assertSame($before, $this->snapshot());
        self::assertStringNotContainsString('[written]', $output);
        self::assertStringNotContainsString('tables keep their names', $output);
        self::assertStringContainsString('[note] laravel-authorization\'s tables already carry the prefix `authz_` in its published configuration.', $output);

        foreach (['authz', 'other_'] as $prefix) {

            [$code, $output] = $this->install(['--prefix' => $prefix]);

            self::assertSame(0, $code);
            self::assertSame($before, $this->snapshot());
            self::assertStringNotContainsString('[note]', $output);
            self::assertStringContainsString(' - laravel-authorization\'s tables keep their names', $output);
        }
    }

    /**
     * An application's own migration sharing the base name of one of
     * `laravel-authorization`'s is no conflict once the run prefixes the
     * member's tables, since the two then create different tables: it is noted,
     * and the run succeeds. Without the prefix it is still a conflict.
     *
     * @return void
     */
    public function testANamesakeOfAnAuthorizationMigrationIsNoConflictOnceThePrefixIsWritten(): void
    {
        $contents = "<?php\n\n// The application's own roles table\n";
        $own      = $this->writeScratch('database/migrations/2019_01_01_000000_create_roles_table.php', $contents);

        $this->writeScratch('database/migrations/2020_01_01_000000_create_roles_table.php', $contents);
        $this->writeScratch('database/migrations/2019_01_01_000000_create_permissions_table.php', "<?php\n");

        [$code, $output] = $this->install(['--prefix' => 'authz_']);

        self::assertSame(0, $code, $output);
        self::assertStringEqualsFile($own, $contents);
        self::assertFileExists($this->scratch('database/migrations/2026_04_14_000001_create_roles_table.php'));
        self::assertStringNotContainsString('[conflict]', $output);
        self::assertSame(3, substr_count($output, '[note] '));

        $namesakes = [
            '2019_01_01_000000_create_roles_table.php'       => '2026_04_14_000001_create_roles_table.php',
            '2020_01_01_000000_create_roles_table.php'       => '2026_04_14_000001_create_roles_table.php',
            '2019_01_01_000000_create_permissions_table.php' => '2026_04_14_000002_create_permissions_table.php',
        ];

        foreach ($namesakes as $namesake => $migration) {
            self::assertStringContainsString(
                "[note] {$namesake} shares its base name with {$migration}, published beside it:"
                . ' the two create different tables, since the run prefixed laravel-authorization\'s with `authz_`',
                $output,
            );
        }
    }

    /**
     * A namesake of one of `laravel-authorization`'s migrations stays a
     * conflict when the prefix given can no longer be written, its
     * configuration published before; without a prefix it is one too.
     *
     * @return void
     */
    public function testANamesakeStaysAConflictWhenTheConfigurationWasPublishedBefore(): void
    {
        $this->writeScratch('config/authorization.php', "<?php\n\nreturn [];\n");
        $this->writeScratch('database/migrations/2019_01_01_000000_create_roles_table.php', "<?php\n");

        [$code, $output] = $this->install(['--prefix' => 'authz_']);

        self::assertSame(1, $code);
        self::assertStringNotContainsString('[note]', $output);
        self::assertStringContainsString('[conflict] 2019_01_01_000000_create_roles_table.php shares its base name with 2026_04_14_000001_create_roles_table.php', $output);
    }

    /**
     * With `laravel-authorization`'s configuration tag unregistered, a prefix
     * cannot be written, and is owed.
     *
     * @return void
     */
    public function testAPrefixIsOwedWhileTheConfigurationTagIsUnregistered(): void
    {
        $this->replacePublication('authorization-config', null);

        [$code, $output] = $this->install(['--prefix' => 'authz_']);

        self::assertSame(1, $code);
        self::assertStringContainsString('[missing] No provider registered the `authorization-config` tag', $output);
        self::assertStringNotContainsString('[note]', $output);
        self::assertStringContainsString(' - laravel-authorization\'s tables keep their names', $output);
    }

    /**
     * The prefix covers `laravel-authorization`'s tables alone: a namesake of
     * another member's migration stays a conflict when the run prefixes them.
     *
     * @return void
     */
    public function testANamesakeOfAnotherMembersMigrationStaysAConflictUnderThePrefix(): void
    {
        $this->writeScratch('database/migrations/2019_01_01_000000_create_rate_limits_table.php', "<?php\n");

        [$code, $output] = $this->install(['--prefix' => 'authz_']);

        self::assertSame(1, $code);
        self::assertStringNotContainsString('[note]', $output);
        self::assertStringContainsString(
            '[conflict] 2019_01_01_000000_create_rate_limits_table.php shares its base name with 2026_04_06_000002_create_rate_limits_table.php',
            $output,
        );
    }

    /**
     * A namesake of one of `laravel-authorization`'s migrations stays a
     * conflict when the prefix given cannot be written over the configuration
     * published in the run.
     *
     * @return void
     */
    public function testANamesakeStaysAConflictWhenThePrefixIsNotWritten(): void
    {
        $this->writeScratch('database/migrations/2019_01_01_000000_create_roles_table.php', "<?php\n");
        $this->replacePublication('authorization-config', [dirname(__DIR__, 2) . '/Fixtures/Install/reshaped-authorization.php' => $this->scratch('config/authorization.php')]);

        [$code, $output] = $this->install(['--prefix' => 'authz_']);

        self::assertSame(1, $code);
        self::assertStringNotContainsString('[note]', $output);
        self::assertStringContainsString('[conflict] 2019_01_01_000000_create_roles_table.php shares its base name with 2026_04_14_000001_create_roles_table.php', $output);
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
     * A prefix given once `laravel-authorization`'s configuration is already
     * published is not written, and that is reported.
     *
     * @return void
     */
    public function testAPrefixIsNotWrittenIntoAConfigurationAlreadyPublished(): void
    {
        $file = $this->writeScratch('config/authorization.php', "<?php\n\nreturn [];\n");

        [$code, $output] = $this->install(['--prefix' => 'authz_']);

        self::assertSame(0, $code);
        self::assertStringEqualsFile($file, "<?php\n\nreturn [];\n");
        self::assertStringNotContainsString('[written] authorization.tables', $output);
        self::assertStringContainsString(
            ' - laravel-authorization\'s tables keep their names: its configuration or its migrations were published before, so the prefix was not written.',
            $output,
        );
    }

    /**
     * A prefix given once one of `laravel-authorization`'s migrations is
     * already published is not written, though its configuration is published
     * in the run.
     *
     * @return void
     */
    public function testAPrefixIsNotWrittenOnceAnAuthorizationMigrationIsPublished(): void
    {
        $source = self::packagePath(AuthorizationServiceProvider::class) . '/database/migrations/2026_04_14_000010_create_guardrails_table.php';

        $this->writeScratch('database/migrations/2024_01_01_000000_create_guardrails_table.php', (string) file_get_contents($source));

        [$code, $output] = $this->install(['--prefix' => 'authz_']);

        self::assertSame(0, $code);
        self::assertFileExists($this->scratch('config/authorization.php'));
        self::assertStringNotContainsString('[written] authorization.tables', $output);
        self::assertStringContainsString('tables keep their names', $output);
    }

    /**
     * An authorization configuration published in the run that no longer holds
     * the table name defaults is written nothing, and the prefix is owed.
     *
     * @return void
     */
    public function testAReshapedAuthorizationConfigurationIsOwedThePrefix(): void
    {
        $this->replacePublication('authorization-config', [dirname(__DIR__, 2) . '/Fixtures/Install/reshaped-authorization.php' => $this->scratch('config/authorization.php')]);

        [$code, $output] = $this->install(['--prefix' => 'authz_']);

        self::assertSame(0, $code);
        self::assertStringNotContainsString('[written] authorization.tables', $output);
        self::assertStringContainsString(
            ' - Prefix laravel-authorization\'s tables yourself (`authorization.tables`) before you migrate:'
            . ' its configuration no longer holds the defaults the prefix is written over.',
            $output,
        );
    }

    /**
     * Interactive, the run asks whether to prefix the tables, and prefixes them
     * with the prefix given.
     *
     * @return void
     */
    public function testInteractiveTheRunAsksForThePrefix(): void
    {
        $this->interactively()
            ->expectsConfirmation('Prefix laravel-authorization\'s tables (roles, permissions, policies and the grant tables), whose names may collide with your own?', 'yes')
            ->expectsQuestion('Table prefix', 'iam_')
            ->assertExitCode(0);

        /** @var array{tables: array<string, string>} $configuration */
        $configuration = require $this->scratch('config/authorization.php');

        self::assertSame('iam_roles', $configuration['tables']['roles']);
    }

    /**
     * Interactive, declining the prefix leaves the tables' own names.
     *
     * @return void
     */
    public function testInteractiveDecliningThePrefixLeavesTheNames(): void
    {
        $this->interactively()
            ->expectsConfirmation('Prefix laravel-authorization\'s tables (roles, permissions, policies and the grant tables), whose names may collide with your own?', 'no')
            ->assertExitCode(0);

        /** @var array{tables: array<string, string>} $configuration */
        $configuration = require $this->scratch('config/authorization.php');

        self::assertSame('roles', $configuration['tables']['roles']);
    }

    /**
     * Interactive, nothing is asked once the prefix can no longer be written,
     * nor when `--prefix` gives it, an empty one (no prefix) included.
     *
     * @return void
     */
    public function testInteractiveNothingIsAskedWhenThePrefixCannotBeWrittenOrIsGiven(): void
    {
        $this->interactively(['--prefix' => ''])->assertExitCode(0);

        /** @var array{tables: array<string, string>} $configuration */
        $configuration = require $this->scratch('config/authorization.php');

        self::assertSame('roles', $configuration['tables']['roles']);

        $this->interactively(['--prefix' => 'authz_'])->assertExitCode(0);
        $this->interactively()->assertExitCode(0);
    }

    /**
     * Without interaction nothing is asked and nothing is prefixed, and an
     * empty `--prefix` is no prefix.
     *
     * @return void
     */
    public function testWithoutInteractionNothingIsPrefixed(): void
    {
        [$code] = $this->install(['--prefix' => '']);

        self::assertSame(0, $code);

        /** @var array{tables: array<string, string>} $configuration */
        $configuration = require $this->scratch('config/authorization.php');

        self::assertSame('roles', $configuration['tables']['roles']);
    }

    /**
     * The prefix is offered only while neither `laravel-authorization`'s
     * configuration nor any of its migrations is published, and its tags are
     * registered.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function testThePrefixIsOfferedOnlyBeforeAuthorizationIsPublished(): void
    {
        self::assertTrue($this->installer()->offersTablePrefix());

        $this->replacePublication('authorization-migrations', null);

        self::assertFalse($this->installer()->offersTablePrefix());

        (new \ReflectionProperty(ServiceProvider::class, 'publishGroups'))->setValue(null, $this->publishGroups);

        $this->replacePublication('authorization-config', null);

        self::assertFalse($this->installer()->offersTablePrefix());
    }

    /**
     * A file that cannot be copied, its directory unwritable, stops the run with
     * the exception naming it, in place of the warning the copy raises; every
     * file published before it is kept, and a run once the directory is
     * writable publishes the rest and nothing twice.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function testAFileThatCannotBeCopiedStopsTheRunAndARunOnceWritablePublishesTheRest(): void
    {
        $this->readOnly('lang');

        $failure = $this->failedInstall();

        self::assertMatchesRegularExpression(
            '#^' . preg_quote($this->scratch('lang/vendor/authorization/'), '#') . '\S+\.php could not be published; make its directory writable and run iam:install again\.$#',
            $failure->getMessage(),
        );
        self::assertInstanceOf(\ErrorException::class, $failure->getPrevious());
        self::assertStringStartsWith('mkdir(', $failure->getPrevious()->getMessage());
        self::assertSame(E_WARNING, $failure->getPrevious()->getSeverity());
        self::assertFileExists($this->scratch('config/authentication.php'));
        self::assertFileExists($this->scratch('config/authorization.php'));
        self::assertFileDoesNotExist($this->scratch('config/mfa.php'));

        $published = glob($this->scratch('database/migrations/*.php')) ?: [];

        self::assertNotSame([], $published);

        chmod($this->scratch('lang'), 0755);

        [$code, $output] = $this->install();

        self::assertSame(0, $code);
        self::assertCount(50, glob($this->scratch('database/migrations/*.php')) ?: []);
        self::assertSame(count($published), substr_count($output, '[recognised]'));
        self::assertStringContainsString('[kept] ' . $this->scratch('config/authentication.php'), $output);
        self::assertStringContainsString('[published] ' . $this->scratch('config/mfa.php'), $output);
        self::assertFileExists($this->scratch('lang/vendor/authorization/en/authorization.php'));
    }

    /**
     * A run stopped by a file after audit-log's configuration still writes the
     * audit-log values into that configuration, so the run once the directory
     * is writable keeps it with the values written and owes nothing for them.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function testARunStoppedAfterAuditLogsConfigurationLeavesItsValuesWritten(): void
    {
        $this->readOnly('lang/vendor/audit-log');

        $failure = $this->failedInstall();

        self::assertStringStartsWith($this->scratch('lang/vendor/audit-log/'), $failure->getMessage());

        chmod($this->scratch('lang/vendor/audit-log'), 0755);

        $file = $this->scratch('config/audit-log.php');

        /** @var array{capture: array{laravel: array{except_guards: list<string>}}, definitions: array{require_registered: mixed}} $configuration */
        $configuration = require $file;

        self::assertSame(['api', 'keys'], $configuration['capture']['laravel']['except_guards']);
        self::assertTrue($configuration['definitions']['require_registered']);

        // The run that follows reads the configuration the stopped run wrote,
        // as a new process would
        $this->config()->set('audit-log', $configuration);

        [$code, $output] = $this->install();

        self::assertSame(0, $code);
        self::assertStringContainsString('[kept] ' . $file, $output);
        self::assertStringNotContainsString(' to `audit-log.capture.laravel.except_guards`', $output);
        self::assertStringNotContainsString('Turn `audit-log.definitions.require_registered` on', $output);
        self::assertFileExists($this->scratch('lang/vendor/audit-log/en/codes.php'));
    }

    /**
     * A run stopped by a file after `laravel-authorization`'s configuration
     * still writes the prefix into that configuration, so the run once the
     * directory is writable notes the prefix carried and owes none.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function testARunStoppedAfterTheAuthorizationConfigurationLeavesThePrefixWritten(): void
    {
        $this->readOnly('lang');

        try {
            $this->installer()->install('authz_');

            self::fail('iam:install published every file.');
        } catch (PublicationFailedException $failure) {
            self::assertStringStartsWith($this->scratch('lang/vendor/authorization/'), $failure->getMessage());
        }

        chmod($this->scratch('lang'), 0755);

        /** @var array{tables: array<string, string>} $configuration */
        $configuration = require $this->scratch('config/authorization.php');

        self::assertCount(10, $configuration['tables']);

        foreach ($configuration['tables'] as $key => $table) {
            self::assertSame('authz_' . $key, $table);
        }

        [$code, $output] = $this->install(['--prefix' => 'authz_']);

        self::assertSame(0, $code);
        self::assertStringContainsString('[note] laravel-authorization\'s tables already carry the prefix `authz_` in its published configuration.', $output);
        self::assertStringNotContainsString('tables keep their names', $output);
    }

    /**
     * A file whose directory exists but cannot be written to stops the run
     * alike, with the copy's warning as the cause, and the application's error
     * handler is back in place once the run has stopped.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function testAFileThatCannotBeCopiedIntoItsDirectoryStopsTheRunAndLeavesTheErrorHandler(): void
    {
        $this->readOnly('config');

        $failure = $this->failedInstall();

        self::assertSame($this->scratch('config/authentication.php') . ' could not be published; make its directory writable and run iam:install again.', $failure->getMessage());
        self::assertInstanceOf(\ErrorException::class, $failure->getPrevious());
        self::assertStringStartsWith('copy(', $failure->getPrevious()->getMessage());
        self::assertSame([], glob($this->scratch('config/*')) ?: []);

        $this->expectException(\ErrorException::class);

        trigger_error('The application\'s error handler raises this.', E_USER_WARNING);
    }

    /**
     * Point the application's configuration, database and language directories
     * at the test's own, and add an `api_key` guard beside the `jwt` one,
     * before any provider registers.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function resolveApplicationConfiguration(mixed $app): void
    {
        parent::resolveApplicationConfiguration($app);

        assert($app instanceof Application);

        $app->useConfigPath($this->scratch('config'));
        $app->useDatabasePath($this->scratch('database'));
        $app->useLangPath($this->scratch('lang'));

        $app->make(ConfigRepository::class)->set('auth.guards.keys', ['driver' => 'api_key', 'provider' => 'people']);
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
     * Run the installer `iam:install` hands its run to, without a prefix, as a
     * run without interaction asks it, expecting it to stop on a file it cannot
     * publish, and return the exception it stopped with.
     *
     * @return \SineMacula\Laravel\Iam\Exceptions\PublicationFailedException
     *
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    private function failedInstall(): PublicationFailedException
    {
        try {
            $this->installer()->install(null);
        } catch (PublicationFailedException $exception) {
            return $exception;
        }

        self::fail('iam:install published every file.');
    }

    /**
     * Create a directory of the test's that nothing can be written to, made
     * writable again once the test ends.
     *
     * @param  string  $path
     * @return void
     */
    private function readOnly(string $path): void
    {
        $directory = $this->scratch($path);

        (new Filesystem)->ensureDirectoryExists($directory);

        chmod($directory, 0555);

        $this->readOnly[] = $directory;

        self::assertFalse(is_writable($directory), 'The test cannot make a directory read-only for this user.');
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

        assert($command instanceof PendingCommand);

        return $command;
    }

    /**
     * Return the installer, as the command is given it.
     *
     * @return \SineMacula\Laravel\Iam\Install\Installer
     */
    private function installer(): Installer
    {
        $installer = $this->app?->make(Installer::class);

        assert($installer instanceof Installer);

        return $installer;
    }

    /**
     * Return the configuration repository.
     *
     * @return \Illuminate\Config\Repository
     */
    private function config(): ConfigRepository
    {
        $config = $this->app?->make(ConfigRepository::class);

        assert($config instanceof ConfigRepository);

        return $config;
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
     * Return every file in the test's directory with a hash of its contents.
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
     * Collapse runs of the same entry into one.
     *
     * @param  list<string>  $entries
     * @return list<string>
     */
    private static function collapse(array $entries): array
    {
        $collapsed = [];

        foreach ($entries as $entry) {

            if (end($collapsed) === $entry) {
                continue;
            }

            $collapsed[] = $entry;
        }

        return $collapsed;
    }

    /**
     * Return the root of the package a provider ships.
     *
     * @param  class-string<\Illuminate\Support\ServiceProvider>  $provider
     * @return string
     */
    private static function packagePath(string $provider): string
    {
        return dirname((string) (new \ReflectionClass($provider))->getFileName(), 2);
    }
}
