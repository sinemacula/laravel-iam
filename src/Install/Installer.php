<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Install;

use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Iam\Audit\AuditSettings;
use SineMacula\Laravel\Iam\Audit\CaptureExclusions;
use SineMacula\Laravel\Iam\Exceptions\PublicationFailedException;
use SineMacula\Laravel\Iam\Install\Enums\PublicationKind;

/**
 * Installs the suite into the application (IAM-2.1): publishes every member's
 * configuration, language files and migrations, and this package's own
 * configuration, in their working order (`Publications`), each file to where
 * its provider publishes it; writes the values of audit-log's configuration
 * this package needs (decision Q5 (a)) and, when asked, prefixed names for
 * `laravel-authorization`'s tables (IAM-2.4), each only into a configuration
 * file published in the same run, as soon as it is published, so a run that
 * stops on a later file leaves none of them unwritten; and reports what it did
 * and what the application still owes.
 *
 * It changes nothing it did not publish, so it is safe to run twice: a
 * configuration file or a language file already there is left as it is, and a
 * member's migration already published, under any timestamp, is recognised by
 * its base name (`MigrationLedger`) and never published again. Nothing is ever
 * overwritten. Where a migration's identity is in doubt the run fails closed,
 * as incomplete, rather than report success: a file at the very path a member's
 * migration is published to that is not the member's copy is kept and the
 * migration left unpublished, a conflict until the application moves it; and a
 * migration of the application's own sharing a member's base name is a conflict
 * of the run that finds it, the member's migration published beside it so its
 * table is never left uncreated without a word, and recognised by every later
 * run. Where a value cannot be written, because the file was there already or
 * no longer holds the member's default, it is reported as owed, and `iam:check`
 * refuses the configuration until it holds. A tag no provider registered is
 * reported, and the run is incomplete too; a member registers its tags only in
 * the console.
 *
 * Everything the run reads from the configuration is read before any file is
 * published, so a malformed value (an `except_guards` that is no list of guard
 * names, a prefix that is not one) refuses the run with nothing changed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Installer
{
    /** @var list<string> What the application owes after every run. */
    public const array OWED = [
        'Run `php artisan migrate`: laravel-authentication\'s, laravel-mfa\'s, laravel-sso\'s and laravel-authorization\'s tables are'
            . ' created on `iam.storage.connection`, and laravel-audit-log\'s on `audit-log.storage.connection`, each the default'
            . ' connection when unset.',
        'Bind laravel-authentication\'s `OneTimeCodeSender`, which delivers every email and SMS code, laravel-mfa\'s included,'
            . ' before you allow a code sign-in method or an `email` or `sms` factor.',
        'Name your tenant MFA requirement, memberships and tenant tree in `iam.tenancy`, or bind them, if your application has tenants.',
        'Bind laravel-authentication\'s `TenantResolver`, resolving every tenant id to the tenant whose `getTenantIdentifier()` is that id,'
            . ' before you grant anything in a tenant through laravel-authorization while laravel-iam\'s authorization and SSO adapters are on'
            . ' (they are by default), name a tenant MFA requirement or turn laravel-sso\'s enforcement on, even if your principals act only'
            . ' in their own tenant: under its default `ResolveNoTenant`, the grant hook, the principal scope\'s grant half,'
            . ' `AdministrativeCheck` for an object in a tenant, laravel-mfa\'s tenant requirement, `Iam::treeChanges()` and'
            . ' laravel-sso\'s revocation throw `UnresolvedReferenceException`.',
        'Name your provisioner in `iam.provisioning.provisioner`, or bind it, to provision people signing in through SSO for the first time.',
        'Add the routes, following laravel-iam\'s example application guide (docs/guides/example-application.md): redeem SSO\'s handoffs'
            . ' through `Iam::signIns()`, `Iam::reauthentications()` and `Iam::links()`, never `HandoffRedemption` directly;'
            . ' laravel-authentication\'s, laravel-mfa\'s and laravel-sso\'s guides list their own routes.',
        'Call `Iam::schedule($schedule)` from `withSchedule()` and run the scheduler.',
        'Run a queue worker for laravel-authentication\'s delivery of one-time codes (`authentication.delivery.queue.connection`'
            . ' and `authentication.delivery.queue.name`), which laravel-mfa\'s email and SMS codes go through too,'
            . ' and, while laravel-sso is in use, for its metadata refresh (`sso.metadata.queue`):'
            . ' see laravel-iam\'s operations guide (docs/guides/operations.md#queues).',
        'Allow the `simplesamlphp/composer-xmlprovider-installer` plugin in your application\'s `composer.json` (`config.allow-plugins`).',
        'Map each application to the permission to use it in `authorization.application_access`: laravel-iam answers'
            . ' laravel-authentication\'s application access from laravel-authorization, which admits any principal to an application'
            . ' the map does not name; and bind laravel-authentication\'s `TenantAccess` if your principals act beyond their own tenant.',
        'Declare laravel-mfa\'s `mfa.*` freshness operations under `authentication.freshness`, or a guard\'s own `freshness`,'
            . ' for every MFA application\'s guard and, while SSO is in use, laravel-sso\'s `sso.*` ones for every SSO application\'s'
            . ' guard, whose sign-in methods must allow `external_provider`; `iam:check` refuses each one missing.',
        'Keep every `jwt` and `api_key` guard you add in `audit-log.capture.laravel.except_guards`.',
        'Define every audit code your application records itself with `AuditLog::define()`: while `audit-log.definitions.require_registered`'
            . ' is on, recording a code with no definition throws.',
        'Run `php artisan iam:check` on every deploy.',
    ];

    /** @var string The conflict of a migration of the application's own that shares a member's base name. */
    private const string NAMESAKE = '%s shares its base name with %s, published beside it: check the two create no table in common before you migrate,'
        . ' as the member\'s collision guard refuses one both create.';

    /** @var string The note of a migration of the application's own sharing the base name of one of `laravel-authorization`'s, whose tables the run prefixed. */
    private const string PREFIXED_NAMESAKE = '%s shares its base name with %s, published beside it: the two create different tables,'
        . ' since the run prefixed laravel-authorization\'s with `%s`, unless an `AUTHORIZATION_TABLE_*` variable names one otherwise.';

    /** @var string The conflict of a file at the path a member's migration is published to that is not the member's copy. */
    private const string BLOCKED = '%s is where %s publishes its migration, but is not its copy, so the migration was not published:'
        . ' move it and run the command again.';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Filesystem\Filesystem  $files
     * @param  \SineMacula\Laravel\Iam\Audit\CaptureExclusions  $exclusions
     * @param  \SineMacula\Laravel\Iam\Audit\AuditSettings  $auditSettings
     * @param  \SineMacula\Laravel\Iam\Install\AuditLogConfiguration  $auditLog
     * @param  \SineMacula\Laravel\Iam\Install\AuthorizationTablePrefix  $tablePrefix
     */
    public function __construct(

        /** The filesystem every file is published through. */
        private Filesystem $files,

        /** The guards audit-log's capture must leave alone, and whether its Gate capture is off. */
        private CaptureExclusions $exclusions,

        /** Whether audit-log refuses a code no definition registers. */
        private AuditSettings $auditSettings,

        /** The writer of audit-log's published configuration file. */
        private AuditLogConfiguration $auditLog,

        /** The writer of prefixed names into `laravel-authorization`'s published configuration file. */
        private AuthorizationTablePrefix $tablePrefix,
    ) {}

    /**
     * Whether prefixed names for `laravel-authorization`'s tables can still be
     * written: neither its configuration file nor any of its migrations has
     * been published yet, so none of its tables has a name yet.
     *
     * @return bool
     *
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function offersTablePrefix(): bool
    {
        return $this->prefixableConfiguration() !== null;
    }

    /**
     * Publish everything not yet published, write what this package needs into
     * the configuration files published, prefixing `laravel-authorization`'s
     * tables when a prefix is given, and report the run.
     *
     * @param  ?string  $tablePrefix
     * @return \SineMacula\Laravel\Iam\Install\InstallReport
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\PublicationFailedException
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function install(?string $tablePrefix): InstallReport
    {
        if ($tablePrefix !== null) {
            AuthorizationTablePrefix::assertValid($tablePrefix);
        }

        $exceptGuards = $this->exclusions->exceptGuards();
        $unexcluded   = $this->exclusions->unexcludedGuards();
        $prefixable   = $tablePrefix !== null ? $this->prefixableConfiguration() : null;

        $ledger   = new MigrationLedger($this->files);
        $run      = [[], [], [], [], [], []];
        $written  = [];
        $owed     = [];
        $notes    = [];
        $prefixed = false;

        // Each configuration's values are written as soon as the file is
        // published, before the next file is copied, so a run that stops on a
        // later file leaves none of them unwritten in a file it published,
        // which a run after it would keep as it is
        foreach (Publications::all() as $publication) {

            $this->publishTag($publication, $ledger, $run);

            if ($publication->tag === Publications::AUTHORIZATION_CONFIGURATION && $tablePrefix !== null) {
                $prefixed = $this->writeTablePrefix($prefixable, $tablePrefix, $written, $owed, $notes);
            }

            if ($publication->tag !== Publications::AUDIT_LOG_CONFIGURATION) {
                continue;
            }

            $this->writeAuditLog($run[0], $exceptGuards, $unexcluded, $written, $owed);
        }

        [$published, $kept, $recognised, $conflicts, $missing, $namesakes] = $run;

        self::judgeNamesakes($namesakes, $prefixed ? $tablePrefix : null, $conflicts, $notes);

        return new InstallReport($published, $kept, $recognised, $written, $conflicts, $missing, [...$owed, ...self::OWED], $notes);
    }

    /**
     * Report each of the application's migrations sharing a member's base name:
     * a note for a namesake of one of `laravel-authorization`'s in a run that
     * wrote the prefix, since the two then create different tables, and a
     * conflict otherwise.
     *
     * @param  list<array{string, string, string}>  $namesakes
     * @param  ?string  $prefix
     * @param  list<string>  $conflicts
     * @param  list<string>  $notes
     * @return void
     */
    private static function judgeNamesakes(array $namesakes, ?string $prefix, array &$conflicts, array &$notes): void
    {
        foreach ($namesakes as [$namesake, $migration, $tag]) {

            if ($prefix !== null && $tag === Publications::AUTHORIZATION_MIGRATIONS) {
                $notes[] = sprintf(self::PREFIXED_NAMESAKE, $namesake, $migration, $prefix);

                continue;
            }

            $conflicts[] = sprintf(self::NAMESAKE, $namesake, $migration);
        }
    }

    /**
     * Publish every file of one tag, recording a tag no provider registered in
     * the run.
     *
     * @param  \SineMacula\Laravel\Iam\Install\Publication  $publication
     * @param  \SineMacula\Laravel\Iam\Install\MigrationLedger  $ledger
     * @param  array{list<string>, list<string>, array<string, string>, list<string>, list<string>, list<array{string, string, string}>}  $run
     * @return void
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\PublicationFailedException
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    private function publishTag(Publication $publication, MigrationLedger $ledger, array &$run): void
    {
        $files = $this->filesOf($publication->tag);

        if ($files === []) {
            $run[4][] = $publication->tag;
        }

        foreach ($files as $source => $destination) {
            $this->publishFile($publication, $ledger, $source, $destination, $run);
        }
    }

    /**
     * Publish one file, unless it is a member's migration already published
     * under its base name, or a file is already where it would be published,
     * and record which in the run: a conflict for a file at a migration's path
     * that is not the member's copy, and every migration of the application's
     * own sharing a member's base name, with the member's and its tag, whose
     * conflict waits on whether the run writes the prefix.
     *
     * @param  \SineMacula\Laravel\Iam\Install\Publication  $publication
     * @param  \SineMacula\Laravel\Iam\Install\MigrationLedger  $ledger
     * @param  string  $source
     * @param  string  $destination
     * @param  array{list<string>, list<string>, array<string, string>, list<string>, list<string>, list<array{string, string, string}>}  $run
     * @return void
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\PublicationFailedException
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    private function publishFile(Publication $publication, MigrationLedger $ledger, string $source, string $destination, array &$run): void
    {
        if ($publication->kind === PublicationKind::MIGRATIONS) {
            $copy = $ledger->copyOf($destination, $publication->namespace);

            if ($copy !== null) {
                $run[2][$destination] = $copy;

                return;
            }

            if ($this->files->exists($destination)) {
                $run[3][] = sprintf(self::BLOCKED, basename($destination), $publication->tag);

                return;
            }

            foreach ($ledger->namesakesOf($destination, $publication->namespace) as $namesake) {
                $run[5][] = [basename($namesake), basename($destination), $publication->tag];
            }
        }

        if ($this->files->exists($destination)) {
            $run[1][] = $destination;

            return;
        }

        $this->copy($source, $destination);

        $run[0][] = $destination;
    }

    /**
     * Write the guards to exclude and the refusal of unregistered codes into
     * audit-log's configuration file when this run published it, and owe each
     * value that does not hold; owe Gate capture turned off while it is on.
     *
     * @param  list<string>  $published
     * @param  list<string>  $exceptGuards
     * @param  list<string>  $unexcluded
     * @param  array<string, string>  $written
     * @param  list<string>  $owed
     * @return void
     *
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    private function writeAuditLog(array $published, array $exceptGuards, array $unexcluded, array &$written, array &$owed): void
    {
        $file = self::destinationOf(Publications::AUDIT_LOG_CONFIGURATION);

        [$unexcluded, $refusesRegistered] = $file !== null && in_array($file, $published, true)
            ? $this->writeAuditLogFile($file, $exceptGuards, $written)
            : [$unexcluded, $this->auditSettings->refusesUnregisteredCodes()];

        if ($unexcluded !== []) {
            $owed[] = sprintf('Add %s to `%s`, so nothing the suite records is recorded twice.', self::listOf($unexcluded), CaptureExclusions::EXCEPT_GUARDS_KEY);
        }

        if (!$refusesRegistered) {
            $owed[] = sprintf('Turn `%s` on (`true`), so a code no definition registers is refused rather than recorded unchecked.', AuditSettings::REQUIRE_REGISTERED);
        }

        if ($this->exclusions->isGateCaptureOff()) {
            return;
        }

        $owed[] = sprintf('Turn audit-log\'s Gate capture off (`%s`): laravel-authorization\'s decisions are recorded from its own events.', CaptureExclusions::GATE_KEY);
    }

    /**
     * Write the guards to exclude and the refusal of unregistered codes into
     * audit-log's configuration file this run published, record each key
     * written, and return the guards still not excluded and whether the refusal
     * is on.
     *
     * @param  string  $file
     * @param  list<string>  $exceptGuards
     * @param  array<string, string>  $written
     * @return array{list<string>, bool}
     *
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    private function writeAuditLogFile(string $file, array $exceptGuards, array &$written): array
    {
        $keys              = $this->auditLog->write($file, $exceptGuards);
        $excluded          = in_array(CaptureExclusions::EXCEPT_GUARDS_KEY, $keys, true);
        $refusesRegistered = in_array(AuditSettings::REQUIRE_REGISTERED, $keys, true);

        if ($excluded) {
            $written[CaptureExclusions::EXCEPT_GUARDS_KEY] = self::listOf($exceptGuards);
        }

        if ($refusesRegistered) {
            $written[AuditSettings::REQUIRE_REGISTERED] = 'true';
        }

        return [$excluded ? [] : $exceptGuards, $refusesRegistered];
    }

    /**
     * Write the prefixed table names into `laravel-authorization`'s
     * configuration file, which this run published while none of its tables had
     * a name yet, and answer whether any was written; or, where the prefix can
     * no longer be written, note that the configuration published before
     * already carries it, or owe it.
     *
     * @param  ?string  $file
     * @param  string  $tablePrefix
     * @param  array<string, string>  $written
     * @param  list<string>  $owed
     * @param  list<string>  $notes
     * @return bool
     *
     * @throws \InvalidArgumentException
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    private function writeTablePrefix(?string $file, string $tablePrefix, array &$written, array &$owed, array &$notes): bool
    {
        if ($file === null) {
            $this->judgeTablePrefix($tablePrefix, $owed, $notes);

            return false;
        }

        $tables = $this->tablePrefix->apply($file, $tablePrefix);

        if ($tables === []) {
            $owed[] = 'Prefix laravel-authorization\'s tables yourself (`authorization.tables`) before you migrate:'
                . ' its configuration no longer holds the defaults the prefix is written over.';
        }

        foreach ($tables as $key => $table) {
            $written['authorization.tables.' . $key] = $table;
        }

        return $tables !== [];
    }

    /**
     * Note that `laravel-authorization`'s configuration, published before,
     * already carries the prefix on every table name it defaults to, as a run
     * before this one wrote it; owe the prefix otherwise.
     *
     * @param  string  $tablePrefix
     * @param  list<string>  $owed
     * @param  list<string>  $notes
     * @return void
     *
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    private function judgeTablePrefix(string $tablePrefix, array &$owed, array &$notes): void
    {
        $file = self::destinationOf(Publications::AUTHORIZATION_CONFIGURATION);

        if ($file !== null && $this->tablePrefix->carries($file, $tablePrefix)) {
            $notes[] = sprintf('laravel-authorization\'s tables already carry the prefix `%s` in its published configuration.', $tablePrefix);

            return;
        }

        $owed[] = 'laravel-authorization\'s tables keep their names: its configuration or its migrations were published before, so the prefix was not written.';
    }

    /**
     * Where `laravel-authorization`'s configuration file is published while the
     * prefix can still be written there: it is not there yet and none of
     * its migrations has been published, under any timestamp; `null`
     * otherwise, or when either tag is not registered.
     *
     * @return ?string
     *
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    private function prefixableConfiguration(): ?string
    {
        $configuration = self::destinationOf(Publications::AUTHORIZATION_CONFIGURATION);
        $migrations    = $this->filesOf(Publications::AUTHORIZATION_MIGRATIONS);

        if ($configuration === null || $this->files->exists($configuration) || $migrations === []) {
            return null;
        }

        $ledger = new MigrationLedger($this->files);

        foreach ($migrations as $destination) {

            if ($ledger->copyOf($destination, Publications::AUTHORIZATION_NAMESPACE) !== null) {
                return null;
            }
        }

        return $configuration;
    }

    /**
     * Every file a tag publishes, by its source, with where it is published: a
     * directory's files one by one, in name order, under the directory it is
     * published to.
     *
     * @param  string  $tag
     * @return array<string, string>
     */
    private function filesOf(string $tag): array
    {
        $files = [];

        /** @var array<string, string> $paths */
        $paths = ServiceProvider::pathsToPublish(null, $tag);

        foreach ($paths as $from => $to) {

            if (!$this->files->isDirectory($from)) {
                $files[$from] = $to;

                continue;
            }

            foreach ($this->files->allFiles($from) as $file) {
                $files[$file->getPathname()] = $to . '/' . $file->getRelativePathname();
            }
        }

        return $files;
    }

    /**
     * Copy one file to where it is published, creating its directory, and
     * refuse a file that cannot be, with the warning that stopped it as the
     * cause. The warning is caught by a handler of the copy's own, so the
     * application's error handler, which would raise it as an `\ErrorException`
     * in place of the refusal, never sees it, whatever the application reports.
     *
     * @param  string  $source
     * @param  string  $destination
     * @return void
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\PublicationFailedException
     */
    private function copy(string $source, string $destination): void
    {
        $error = null;

        set_error_handler(static function (int $severity, string $message, string $file = '', int $line = 0) use (&$error): bool {
            $error ??= new \ErrorException($message, 0, $severity, $file, $line);

            return true;
        });

        try {
            $this->files->ensureDirectoryExists(dirname($destination));

            $copied = $this->files->copy($source, $destination);
        } finally {
            restore_error_handler();
        }

        if (!$copied) {
            throw PublicationFailedException::forFile($destination, $error);
        }
    }

    /**
     * Where the one file a configuration tag publishes is published, or `null`
     * when no provider registered the tag.
     *
     * @param  string  $tag
     * @return ?string
     */
    private static function destinationOf(string $tag): ?string
    {
        /** @var array<string, string> $paths */
        $paths = ServiceProvider::pathsToPublish(null, $tag);

        return array_values($paths)[0] ?? null;
    }

    /**
     * Write a list of guards as a PHP array of strings.
     *
     * @param  list<string>  $guards
     * @return string
     */
    private static function listOf(array $guards): string
    {
        return '[' . implode(', ', array_map(static fn (string $guard): string => '\'' . $guard . '\'', $guards)) . ']';
    }
}
