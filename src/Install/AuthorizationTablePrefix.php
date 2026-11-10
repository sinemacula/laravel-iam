<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Install;

use Illuminate\Filesystem\Filesystem;

/**
 * Prefixed names for `laravel-authorization`'s tables (IAM-2.4), whose own
 * names (`roles`, `permissions`, `policies` and the grant tables) are generic
 * enough to collide with an application's.
 *
 * The names are written into the configuration file `iam:install` has just
 * published, as the default of each `AUTHORIZATION_TABLE_*` variable the file
 * reads, so the variable still wins where the application sets one, and
 * `laravel-authorization`'s migrations and models read the prefixed names from
 * the first migration on. A configuration file the application had already
 * published is never written, nor one whose migrations were published before:
 * their tables keep the names they have. A table `laravel-authorization`
 * already names under its own prefix (`OWN_PREFIX`, as its grant usage tables
 * are) collides with nothing, so it keeps that name.
 *
 * A prefix is lower-case letters, digits and underscores, starting with a
 * letter, at most `MAX_LENGTH` characters long: the longest table, index or
 * foreign key name `laravel-authorization`'s migrations derive from a table
 * name is 46 characters before the prefix, so every one stays within
 * PostgreSQL's 63 and MySQL's 64.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AuthorizationTablePrefix
{
    /** @var string The prefix `iam:install` suggests when it asks. */
    public const string SUGGESTED = 'authorization_';

    /** @var int The longest prefix allowed. */
    public const int MAX_LENGTH = 16;

    /** @var string The prefix `laravel-authorization` names some of its own tables with, which collide with nothing. */
    private const string OWN_PREFIX = 'authorization_';

    /** @var string The shape of a prefix. */
    private const string SHAPE = '/^[a-z][a-z0-9_]*$/D';

    /** @var string The default of each table name's variable in `laravel-authorization`'s configuration. */
    private const string TABLE_DEFAULT = '/(\'([a-z_]+)\'\s*=>\s*env\(\s*\'AUTHORIZATION_TABLE_[A-Z_]+\'\s*,\s*\')([a-z0-9_]+)(\'\s*\))/';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Filesystem\Filesystem  $files
     */
    public function __construct(

        /** The filesystem the configuration file is read from and written to. */
        private Filesystem $files,
    ) {}

    /**
     * Refuse a prefix that is not one.
     *
     * @param  string  $prefix
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public static function assertValid(string $prefix): void
    {
        if (preg_match(self::SHAPE, $prefix) === 1 && strlen($prefix) <= self::MAX_LENGTH) {
            return;
        }

        $message = 'The table prefix must be lower-case letters, digits and underscores, start with a letter and be at most %d characters long.';

        throw new \InvalidArgumentException(sprintf($message, self::MAX_LENGTH));
    }

    /**
     * Whether every table name `laravel-authorization`'s published
     * configuration file defaults to is the prefix followed by the table's own
     * name (its key under `authorization.tables`), as a run that wrote the
     * prefix leaves them, a table the package names under its own prefix aside:
     * a prefix that is only the start of the one written (`iam` where `iam_`
     * was written) is not carried, since the tables are not named with it. A
     * file holding no table name default, none but the package's own prefixed
     * ones, or no file there, carries none.
     *
     * @param  string  $file
     * @param  string  $prefix
     * @return bool
     *
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function carries(string $file, string $prefix): bool
    {
        if (!$this->files->isFile($file)) {
            return false;
        }

        preg_match_all(self::TABLE_DEFAULT, $this->files->get($file), $matches);

        $names    = array_combine($matches[2], $matches[3]);
        $prefixed = array_filter($names, static fn (string $table, string $key): bool => $table === $prefix . $key, ARRAY_FILTER_USE_BOTH);
        $own      = array_filter($names, static fn (string $table, string $key): bool => $table === self::OWN_PREFIX . $key, ARRAY_FILTER_USE_BOTH);

        return $prefixed !== [] && count($prefixed + $own) === count($names);
    }

    /**
     * Prefix every table name `laravel-authorization`'s published configuration
     * file defaults to, but those the package names under its own prefix, and
     * return the key under `authorization.tables` of each name written, with
     * the name it now defaults to.
     *
     * @param  string  $file
     * @param  string  $prefix
     * @return array<string, string>
     *
     * @throws \InvalidArgumentException
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function apply(string $file, string $prefix): array
    {
        self::assertValid($prefix);

        $written  = [];
        $contents = (string) preg_replace_callback(self::TABLE_DEFAULT, static function (array $match) use ($prefix, &$written): string {

            if ($match[3] === self::OWN_PREFIX . $match[2]) {
                return $match[0];
            }

            $written[$match[2]] = $prefix . $match[3];

            return $match[1] . $prefix . $match[3] . $match[4];
        }, $this->files->get($file));

        if ($written !== []) {
            $this->files->put($file, $contents);
        }

        return $written;
    }
}
