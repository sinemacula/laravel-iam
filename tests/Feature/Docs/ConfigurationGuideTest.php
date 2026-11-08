<?php

declare(strict_types = 1);

namespace Tests\Feature\Docs;

use Illuminate\Support\Arr;
use PHPUnit\Framework\Attributes\CoversNothing;
use Tests\TestCase;

/**
 * The configuration guide documents every key of `config/iam.php`, each named
 * in full in backticks (`iam.storage.connection`), and names no key of this
 * package's that the file does not hold, so a key added, renamed or removed
 * cannot leave the guide behind.
 *
 * The keys are the file's leaves, read from the file the package ships, never
 * from the application's configuration, so the test reads what an application
 * publishes. A key the guide names is this package's when it starts `iam.`, and
 * it must then be a key of the file, a leaf or a group of them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class ConfigurationGuideTest extends TestCase
{
    /** @var string The guide, from the package root. */
    private const string GUIDE = 'docs/guides/configuration.md';

    /** @var string The configuration file, from the package root. */
    private const string CONFIGURATION = 'config/iam.php';

    /** @var string The pattern a key of this package's matches, named in backticks. */
    private const string KEY = '/`(iam(?:\.[a-z_]+)+)`/';

    /**
     * Every key of the configuration file is named in the guide.
     *
     * @return void
     */
    public function testEveryKeyIsDocumented(): void
    {
        $guide = self::guide();
        $keys  = self::keys();

        self::assertNotEmpty($keys);
        self::assertSame([], self::undocumented($guide, $keys));
    }

    /**
     * Every key of this package's the guide names is a key of the file.
     *
     * @return void
     */
    public function testEveryKeyTheGuideNamesExists(): void
    {
        self::assertSame([], self::unknown(self::guide(), self::configuration()));
    }

    /**
     * A key the guide leaves out is reported.
     *
     * @return void
     */
    public function testAKeyLeftOutIsReported(): void
    {
        $guide = str_replace('`iam.workers.reset`', '`reset`', self::guide());

        self::assertSame(['iam.workers.reset'], self::undocumented($guide, self::keys()));
    }

    /**
     * A key the guide names that the file does not hold is reported.
     *
     * @return void
     */
    public function testAKeyTheFileDoesNotHoldIsReported(): void
    {
        $guide = self::guide() . "\n`iam.workers.retired` and `iam.storage.connection.name`\n";

        self::assertSame(['iam.workers.retired', 'iam.storage.connection.name'], self::unknown($guide, self::configuration()));
    }

    /**
     * The keys of the file the guide does not name, in the file's order.
     *
     * @param  string  $guide
     * @param  list<string>  $keys
     * @return list<string>
     */
    private static function undocumented(string $guide, array $keys): array
    {
        return array_values(array_filter($keys, static fn (string $key): bool => !str_contains($guide, '`' . $key . '`')));
    }

    /**
     * The keys of this package's the guide names that the file does not hold,
     * in the guide's order.
     *
     * @param  string  $guide
     * @param  array<array-key, mixed>  $configuration
     * @return list<string>
     */
    private static function unknown(string $guide, array $configuration): array
    {
        preg_match_all(self::KEY, $guide, $matches);

        $named = array_values(array_unique($matches[1]));

        return array_values(array_filter($named, static fn (string $key): bool => !Arr::has($configuration, substr($key, strlen('iam.')))));
    }

    /**
     * Every leaf key of the file, prefixed `iam.`, in the file's order.
     *
     * @return list<string>
     */
    private static function keys(): array
    {
        return array_map(static fn (int|string $key): string => 'iam.' . $key, array_keys(Arr::dot(self::configuration())));
    }

    /**
     * The configuration file as the package ships it.
     *
     * @return array<array-key, mixed>
     */
    private static function configuration(): array
    {
        $configuration = require self::root() . '/' . self::CONFIGURATION;

        return is_array($configuration) ? $configuration : self::fail('The configuration file returns no array.');
    }

    /**
     * The guide's text.
     *
     * @return string
     */
    private static function guide(): string
    {
        $guide = file_get_contents(self::root() . '/' . self::GUIDE);

        return $guide === false ? self::fail('The configuration guide is missing.') : $guide;
    }

    /**
     * The package root.
     *
     * @return string
     */
    private static function root(): string
    {
        return dirname(__DIR__, 3);
    }
}
