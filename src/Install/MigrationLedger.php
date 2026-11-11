<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Install;

use Illuminate\Filesystem\Filesystem;

/**
 * Recognises a member's published migration by its base name, whatever its
 * timestamp (IAM-2.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class MigrationLedger
{
    /** @var string The timestamp a migration's file name starts with. */
    private const string TIMESTAMP = '/^\d{4}_\d{2}_\d{2}_\d{6}_/';

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
     * The file name of a migration without its timestamp and extension.
     *
     * @param  string  $path
     * @return string
     */
    public static function baseName(string $path): string
    {
        return (string) preg_replace(self::TIMESTAMP, '', basename($path, self::EXTENSION));
    }

    /**
     * The copy of a migration beside its destination that shares its base name
     * and names the member's namespace.
     *
     * @param  string  $destination
     * @param  string  $namespace
     * @return ?string
     *
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function copyOf(string $destination, string $namespace): ?string
    {
        $directory = dirname($destination);

        $this->directories[$directory] ??= $this->read($directory);

        foreach ($this->directories[$directory][self::baseName($destination)] ?? [] as $path) {

            if (str_contains($this->files->get($path), $namespace)) {
                return $path;
            }
        }

        return null;
    }

    /**
     * A directory's own `.php` files, by base name, in file name order.
     *
     * @param  string  $directory
     * @return array<string, list<string>>
     */
    private function read(string $directory): array
    {
        $migrations = [];

        foreach ($this->files->isDirectory($directory) ? $this->files->files($directory) : [] as $file) {

            if (!str_ends_with($file->getFilename(), self::EXTENSION)) {
                continue;
            }

            $migrations[self::baseName($file->getPathname())][] = $file->getPathname();
        }

        return $migrations;
    }
}
