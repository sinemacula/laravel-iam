<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Filesystem\Filesystem;

/**
 * Gives each test a directory of its own under the system's temporary
 * directory, created on first use and deleted once the test ends, for the tests
 * that publish or write files.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait UsesScratchDirectory
{
    /** @var ?non-empty-string The test's directory, once created. */
    private ?string $scratch = null;

    /**
     * Return a path in the test's directory, creating the directory first.
     *
     * @param  string  $path
     * @return non-empty-string
     */
    protected function scratch(string $path = ''): string
    {
        if ($this->scratch === null) {
            $this->scratch = sys_get_temp_dir() . '/laravel-iam-' . getmypid() . '-' . str_replace('.', '', uniqid('', true));

            (new Filesystem)->ensureDirectoryExists($this->scratch);
        }

        return $path === '' ? $this->scratch : $this->scratch . '/' . $path;
    }

    /**
     * Write a file in the test's directory, creating its directory, and return
     * its path.
     *
     * @param  string  $path
     * @param  string  $contents
     * @return string
     */
    protected function writeScratch(string $path, string $contents): string
    {
        $file = $this->scratch($path);

        (new Filesystem)->ensureDirectoryExists(dirname($file));

        file_put_contents($file, $contents);

        return $file;
    }

    /**
     * Delete the test's directory.
     *
     * @return void
     */
    protected function deleteScratch(): void
    {
        if ($this->scratch === null) {
            return;
        }

        (new Filesystem)->deleteDirectory($this->scratch);

        $this->scratch = null;
    }
}
