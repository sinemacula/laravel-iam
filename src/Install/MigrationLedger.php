<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Install;

use Illuminate\Filesystem\Filesystem;

/**
 * The migrations an application has already published, recognised by their base
 * name, never their timestamp (IAM-2.1): `create_mfa_factors_table` is the base
 * name of `2026_04_15_000000_create_mfa_factors_table.php`, and of the same
 * migration an application published with another timestamp, as Laravel's
 * `publishesMigrations()` and an application moving from installing members
 * directly both give one.
 *
 * A file of the same base name counts as the member's copy only while it names
 * the member's namespace, as every member's migration does (each uses the
 * member's collision guard and storage connection): `laravel-authorization`'s
 * base names (`create_roles_table`, `create_permissions_table`,
 * `create_policies_table`) and `laravel-authentication`'s
 * `create_rate_limits_table` are generic enough for an application's own
 * migration to share one, and taking it for the member's would leave the
 * member's table uncreated without a word. Such a namesake is a conflict of the
 * run that finds it instead, and the member's migration is published beside it,
 * so a table the two share is refused loudly by the member's collision guard
 * when it migrates.
 *
 * A directory is read once, when it is first asked about, and only its own
 * `.php` files, as Laravel's migrator reads it. No two of a member's migrations
 * share a base name, and a migration names its own member's namespace alone, so
 * what one run publishes never changes what the ledger answers for the rest of
 * the run.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class MigrationLedger
{
    /** @var string The timestamp a migration's file name starts with. */
    public const string TIMESTAMP = '/^\d{4}_\d{2}_\d{2}_\d{6}_/';

    /** @var string The extension of a migration's file. */
    private const string EXTENSION = '.php';

    /** @var array<string, array<string, list<string>>> The migrations of each directory read, by base name. */
    private array $directories = [];

    /**
     * Constructor.
     *
     * @param  \Illuminate\Filesystem\Filesystem  $files
     */
    public function __construct(

        /** The filesystem the migrations are read from. */
        private readonly Filesystem $files,
    ) {}

    /**
     * The base name of a migration: its file name without the timestamp it
     * starts with and without its extension.
     *
     * @param  string  $path
     * @return string
     */
    public static function baseName(string $path): string
    {
        return (string) preg_replace(self::TIMESTAMP, '', basename($path, self::EXTENSION));
    }

    /**
     * The copy of the given migration already published beside where it would
     * be published, under any timestamp, or `null` when there is none.
     *
     * @param  string  $destination
     * @param  string  $namespace
     * @return ?string
     *
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function copyOf(string $destination, string $namespace): ?string
    {
        foreach ($this->sharingBaseName($destination) as $path) {

            if ($this->names($path, $namespace)) {
                return $path;
            }
        }

        return null;
    }

    /**
     * The application's own migrations that share the given migration's base
     * name without being a copy of it.
     *
     * @param  string  $destination
     * @param  string  $namespace
     * @return list<string>
     *
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function namesakesOf(string $destination, string $namespace): array
    {
        return array_values(array_filter(
            $this->sharingBaseName($destination),
            fn (string $path): bool => !$this->names($path, $namespace),
        ));
    }

    /**
     * Every migration beside the given one that shares its base name, in file
     * name order.
     *
     * @param  string  $destination
     * @return list<string>
     */
    private function sharingBaseName(string $destination): array
    {
        $directory = dirname($destination);

        $this->read($directory);

        return $this->directories[$directory][self::baseName($destination)] ?? [];
    }

    /**
     * Read a directory's migrations by base name, once.
     *
     * @param  string  $directory
     * @return void
     */
    private function read(string $directory): void
    {
        if (isset($this->directories[$directory])) {
            return;
        }

        $migrations = [];

        foreach ($this->files->isDirectory($directory) ? $this->files->files($directory) : [] as $file) {

            if (!str_ends_with($file->getFilename(), self::EXTENSION)) {
                continue;
            }

            $migrations[self::baseName($file->getPathname())][] = $file->getPathname();
        }

        $this->directories[$directory] = $migrations;
    }

    /**
     * Whether a migration names the given namespace.
     *
     * @param  string  $path
     * @param  string  $namespace
     * @return bool
     *
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    private function names(string $path, string $namespace): bool
    {
        return str_contains($this->files->get($path), $namespace);
    }
}
