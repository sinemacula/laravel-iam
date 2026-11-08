<?php

declare(strict_types = 1);

namespace Tests\Unit\Install;

use Illuminate\Filesystem\Filesystem;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\AuditLogServiceProvider;
use SineMacula\Laravel\Iam\Install\AuditLogConfiguration;
use Tests\Concerns\UsesScratchDirectory;

/**
 * Unit tests for writing the values of audit-log's configuration this package
 * needs into its published configuration file (decision Q5 (a), IAM-2.5).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuditLogConfiguration::class)]
final class AuditLogConfigurationTest extends TestCase
{
    use UsesScratchDirectory;

    /**
     * Delete the test's directory and forget the variables a test set.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->deleteScratch();

        putenv('AUDIT_LOG_DEFINITIONS_REQUIRE_REGISTERED');

        parent::tearDown();
    }

    /**
     * The guards are written as the excluded guards and the refusal of
     * unregistered codes is turned on, and nothing else in the file changes:
     * Gate capture stays off.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function testTheGuardsAndTheRefusalAreWritten(): void
    {
        $file   = $this->publishedConfiguration();
        $before = (string) file_get_contents($file);

        $written = (new AuditLogConfiguration(new Filesystem))->write($file, ['api', 'keys']);

        self::assertSame(['audit-log.capture.laravel.except_guards', 'audit-log.definitions.require_registered'], $written);

        $configuration = self::configuration($file);

        self::assertSame(['api', 'keys'], $configuration['capture']['laravel']['except_guards']);
        self::assertTrue($configuration['definitions']['require_registered']);
        self::assertFalse($configuration['capture']['gate']['enabled']);

        $expected = str_replace('\'except_guards\'  => [],', '\'except_guards\'  => [\'api\', \'keys\'],', $before);
        $expected = str_replace('env(\'AUDIT_LOG_DEFINITIONS_REQUIRE_REGISTERED\', false)', 'env(\'AUDIT_LOG_DEFINITIONS_REQUIRE_REGISTERED\', true)', $expected);

        self::assertSame($expected, file_get_contents($file));
    }

    /**
     * The variable the file reads still wins over the default written.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function testTheVariableStillWinsOverTheRefusalWritten(): void
    {
        $file = $this->publishedConfiguration();

        (new AuditLogConfiguration(new Filesystem))->write($file, []);

        putenv('AUDIT_LOG_DEFINITIONS_REQUIRE_REGISTERED=false');

        self::assertFalse(self::configuration($file)['definitions']['require_registered']);
    }

    /**
     * No guard to exclude leaves audit-log's own default, which excludes none.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function testNoGuardsLeaveTheDefault(): void
    {
        $file = $this->publishedConfiguration();

        self::assertSame(['audit-log.definitions.require_registered'], (new AuditLogConfiguration(new Filesystem))->write($file, []));
        self::assertSame([], self::configuration($file)['capture']['laravel']['except_guards']);
    }

    /**
     * A guard's name is written as a PHP string, whatever it holds.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function testAGuardsNameIsWrittenAsAString(): void
    {
        $file = $this->publishedConfiguration();

        (new AuditLogConfiguration(new Filesystem))->write($file, ['o\'brien', 'back\slash', '$1', '*']);

        self::assertSame(['o\'brien', 'back\slash', '$1', '*'], self::configuration($file)['capture']['laravel']['except_guards']);
    }

    /**
     * A file that no longer holds audit-log's defaults, or holds one twice, is
     * left as it is, and nothing is reported written.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function testAFileWithoutTheDefaultsIsLeftAsItIs(): void
    {
        $contents = "<?php\n\nreturn ['capture' => ['laravel' => ['except_guards' => ['web']]], 'a' => ['except_guards' => []],"
            . " 'b' => ['except_guards' => []], 'definitions' => ['require_registered' => true]];\n";
        $file = $this->writeScratch('config/audit-log.php', $contents);

        touch($file, time() - 60);
        clearstatcache();

        $mtime = filemtime($file);

        self::assertSame([], (new AuditLogConfiguration(new Filesystem))->write($file, ['api']));
        self::assertSame($contents, file_get_contents($file));

        clearstatcache();

        self::assertSame($mtime, filemtime($file));
    }

    /**
     * Copy audit-log's configuration file into the test's directory, as
     * `iam:install` publishes it.
     *
     * @return string
     */
    private function publishedConfiguration(): string
    {
        $provider = (string) (new \ReflectionClass(AuditLogServiceProvider::class))->getFileName();

        return $this->writeScratch('config/audit-log.php', (string) file_get_contents(dirname($provider, 2) . '/config/audit-log.php'));
    }

    /**
     * Load a configuration file.
     *
     * @param  string  $file
     * @return array{capture: array{laravel: array{except_guards: list<string>}, gate: array{enabled: mixed}}, definitions: array{require_registered: mixed}}
     */
    private static function configuration(string $file): array
    {
        /** @var array{capture: array{laravel: array{except_guards: list<string>}, gate: array{enabled: mixed}}, definitions: array{require_registered: mixed}} */
        return require $file;
    }
}
