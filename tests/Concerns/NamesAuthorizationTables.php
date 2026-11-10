<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;

/**
 * The table names and migrations `laravel-authorization` ships, read from the
 * installed package, so a test of the table prefix follows whatever tables the
 * package adds.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
trait NamesAuthorizationTables
{
    /**
     * The name each of `laravel-authorization`'s tables takes under the prefix,
     * keyed by its key under `authorization.tables`: the prefix followed by the
     * name the package ships, or that name alone where it already starts with
     * the prefix.
     *
     * @param  string  $prefix
     * @return array<string, string>
     */
    protected static function prefixedAuthorizationTables(string $prefix): array
    {
        /** @var array{tables: array<string, string>} $configuration */
        $configuration = require self::authorizationPackagePath() . '/config/authorization.php';

        return array_map(static fn (string $name): string => str_starts_with($name, $prefix) ? $name : $prefix . $name, $configuration['tables']);
    }

    /**
     * The file names of the migrations `laravel-authorization` ships.
     *
     * @return list<string>
     */
    protected static function authorizationMigrations(): array
    {
        return array_map(basename(...), glob(self::authorizationPackagePath() . '/database/migrations/*.php') ?: []);
    }

    /**
     * The root of the installed `laravel-authorization` package.
     *
     * @return string
     */
    private static function authorizationPackagePath(): string
    {
        return dirname((string) (new \ReflectionClass(AuthorizationServiceProvider::class))->getFileName(), 2);
    }
}
