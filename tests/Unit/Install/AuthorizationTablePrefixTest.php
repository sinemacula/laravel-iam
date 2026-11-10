<?php

declare(strict_types = 1);

namespace Tests\Unit\Install;

use Illuminate\Filesystem\Filesystem;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Iam\Install\AuthorizationTablePrefix;
use Tests\Concerns\NamesAuthorizationTables;
use Tests\Concerns\UsesScratchDirectory;

/**
 * Unit tests for writing prefixed names for `laravel-authorization`'s tables
 * into its published configuration file (IAM-2.4).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationTablePrefix::class)]
final class AuthorizationTablePrefixTest extends TestCase
{
    use NamesAuthorizationTables, UsesScratchDirectory;

    /**
     * Delete the test's directory and forget the variables a test set.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->deleteScratch();

        putenv('AUTHORIZATION_TABLE_ROLES');

        parent::tearDown();
    }

    /**
     * Every table name `laravel-authorization`'s configuration defaults to is
     * prefixed, and nothing else in the file changes.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function testEveryTableNameIsPrefixed(): void
    {
        $file    = $this->publishedConfiguration();
        $before  = (string) file_get_contents($file);
        $written = (new AuthorizationTablePrefix(new Filesystem))->apply($file, 'authz_');

        $shipped  = self::prefixedAuthorizationTables('');
        $expected = self::prefixedAuthorizationTables('authz_');

        self::assertSame($expected, $written);
        self::assertSame($expected, self::configuration($file)['tables']);

        foreach ($shipped as $key => $table) {
            $variable = 'AUTHORIZATION_TABLE_' . strtoupper($key);
            $before   = str_replace("env('{$variable}', '{$table}')", "env('{$variable}', '{$expected[$key]}')", $before);
        }

        self::assertSame($before, file_get_contents($file));
    }

    /**
     * A table whose default the application changed before is prefixed under
     * its own key, the name it defaults to kept after the prefix.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function testAChangedDefaultIsPrefixedUnderItsKey(): void
    {
        $file = $this->writeScratch('config/authorization.php', "<?php\n\nreturn ['tables' => ['roles' => env('AUTHORIZATION_TABLE_ROLES', 'app_roles')]];\n");

        self::assertSame(['roles' => 'authz_app_roles'], (new AuthorizationTablePrefix(new Filesystem))->apply($file, 'authz_'));
        self::assertSame(['roles' => 'authz_app_roles'], self::configuration($file)['tables']);
    }

    /**
     * The variable the file reads still wins over the prefixed default.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function testTheVariableStillWinsOverThePrefixedDefault(): void
    {
        $file = $this->publishedConfiguration();

        (new AuthorizationTablePrefix(new Filesystem))->apply($file, 'authz_');

        putenv('AUTHORIZATION_TABLE_ROLES=custom_roles');

        self::assertSame('custom_roles', self::configuration($file)['tables']['roles']);
    }

    /**
     * A file that no longer holds the defaults is left as it is, and nothing is
     * reported written.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function testAFileWithoutTheDefaultsIsLeftAsItIs(): void
    {
        $contents = "<?php\n\nreturn ['tables' => ['roles' => 'my_roles']];\n";
        $file     = $this->writeScratch('config/authorization.php', $contents);

        touch($file, time() - 60);
        clearstatcache();

        $mtime = filemtime($file);

        self::assertSame([], (new AuthorizationTablePrefix(new Filesystem))->apply($file, 'authz_'));
        self::assertSame($contents, file_get_contents($file));

        clearstatcache();

        self::assertSame($mtime, filemtime($file));
    }

    /**
     * Provide valid prefixes.
     *
     * @return iterable<string, array{string}>
     */
    public static function validPrefixes(): iterable
    {
        yield 'the suggestion' => [AuthorizationTablePrefix::SUGGESTED];
        yield 'one letter' => ['a'];
        yield 'letters, digits and underscores' => ['iam2_authz_'];
        yield 'the longest' => [str_repeat('a', AuthorizationTablePrefix::MAX_LENGTH)];
    }

    /**
     * A valid prefix is accepted.
     *
     * @param  string  $prefix
     * @return void
     */
    #[DataProvider('validPrefixes')]
    public function testAValidPrefixIsAccepted(string $prefix): void
    {
        AuthorizationTablePrefix::assertValid($prefix);

        $this->addToAssertionCount(1);
    }

    /**
     * Provide prefixes that are not one.
     *
     * @return iterable<string, array{string}>
     */
    public static function invalidPrefixes(): iterable
    {
        yield 'empty' => [''];
        yield 'a digit first' => ['2fa_'];
        yield 'an underscore first' => ['_authz'];
        yield 'upper case' => ['Authz_'];
        yield 'a hyphen' => ['authz-'];
        yield 'a quote' => ['authz\''];
        yield 'a newline after' => ["authz\n"];
        yield 'too long' => [str_repeat('a', AuthorizationTablePrefix::MAX_LENGTH + 1)];
    }

    /**
     * A prefix that is not one is refused, before the file is read.
     *
     * @param  string  $prefix
     * @return void
     *
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    #[DataProvider('invalidPrefixes')]
    public function testAnInvalidPrefixIsRefused(string $prefix): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The table prefix must be lower-case letters, digits and underscores, start with a letter and be at most 16 characters long.');

        (new AuthorizationTablePrefix(new Filesystem))->apply($this->scratch('missing.php'), $prefix);
    }

    /**
     * A configuration carries the prefix only while every table name it
     * defaults to starts with it, a prefix holding digits included; one with no
     * table name default carries none, nor does a path holding no file.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function testWhetherAConfigurationCarriesThePrefix(): void
    {
        $prefixer = new AuthorizationTablePrefix(new Filesystem);
        $file     = $this->publishedConfiguration();

        self::assertFalse($prefixer->carries($file, 'authz2_'));

        $prefixer->apply($file, 'authz2_');

        self::assertTrue($prefixer->carries($file, 'authz2_'));
        self::assertFalse($prefixer->carries($file, 'other_'));
        self::assertFalse($prefixer->carries($file, 'authz2'));
        self::assertFalse($prefixer->carries($file, 'authz'));
        self::assertFalse($prefixer->carries($file, 'a'));

        $partly = $this->writeScratch('config/partly.php', "<?php\n\nreturn ['tables' => [\n"
            . "    'roles' => env('AUTHORIZATION_TABLE_ROLES', 'authz_roles'),\n"
            . "    'permissions' => env('AUTHORIZATION_TABLE_PERMISSIONS', 'permissions'),\n]];\n");

        self::assertFalse($prefixer->carries($partly, 'authz_'));
        self::assertFalse($prefixer->carries($this->writeScratch('config/empty.php', "<?php\n\nreturn ['tables' => ['roles' => 'authz_roles']];\n"), 'authz_'));
        self::assertFalse($prefixer->carries($this->scratch('config/missing.php'), 'authz_'));
        self::assertFalse($prefixer->carries($this->scratch('config'), 'authz_'));
    }

    /**
     * A table `laravel-authorization` already ships under a name starting with
     * the prefix keeps that name, rather than carrying the prefix twice, and
     * the configuration then carries the prefix.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function testANameThatAlreadyStartsWithThePrefixKeepsIt(): void
    {
        $prefixer = new AuthorizationTablePrefix(new Filesystem);
        $file     = $this->writeScratch('config/authorization.php', "<?php\n\nreturn ['tables' => [\n"
            . "    'roles' => env('AUTHORIZATION_TABLE_ROLES', 'roles'),\n"
            . "    'grant_usage' => env('AUTHORIZATION_TABLE_GRANT_USAGE', 'authorization_grant_usage'),\n]];\n");

        $written = $prefixer->apply($file, 'authorization_');

        self::assertSame(['roles' => 'authorization_roles', 'grant_usage' => 'authorization_grant_usage'], $written);
        self::assertSame($written, self::configuration($file)['tables']);
        self::assertTrue($prefixer->carries($file, 'authorization_'));
    }

    /**
     * The suggested prefix and the longest allowed.
     *
     * @return void
     */
    public function testTheSuggestionAndTheLongestPrefix(): void
    {
        self::assertSame('authorization_', AuthorizationTablePrefix::SUGGESTED);
        self::assertSame(16, AuthorizationTablePrefix::MAX_LENGTH);
    }

    /**
     * Copy `laravel-authorization`'s configuration file into the test's
     * directory, as `iam:install` publishes it.
     *
     * @return string
     */
    private function publishedConfiguration(): string
    {
        $provider = (string) (new \ReflectionClass(AuthorizationServiceProvider::class))->getFileName();

        return $this->writeScratch('config/authorization.php', (string) file_get_contents(dirname($provider, 2) . '/config/authorization.php'));
    }

    /**
     * Load a configuration file.
     *
     * @param  string  $file
     * @return array{tables: array<string, string>}
     */
    private static function configuration(string $file): array
    {
        /** @var array{tables: array<string, string>} */
        return require $file;
    }
}
