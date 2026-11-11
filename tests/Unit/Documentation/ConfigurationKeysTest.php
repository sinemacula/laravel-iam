<?php

declare(strict_types = 1);

namespace Tests\Unit\Documentation;

use Illuminate\Support\Arr;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * The guides' `iam.*` configuration keys match `config/iam.php`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class ConfigurationKeysTest extends TestCase
{
    /**
     * Every key of the configuration file is named in the configuration guide.
     *
     * @return void
     */
    public function testEveryKeyIsDocumented(): void
    {
        $guide = (string) file_get_contents(self::root() . '/docs/guides/configuration.md');
        $keys  = array_map(static fn (int|string $key): string => 'iam.' . $key, array_keys(Arr::dot(self::configuration())));

        self::assertNotEmpty($keys);
        self::assertSame([], array_values(array_filter($keys, static fn (string $key): bool => !str_contains($guide, '`' . $key . '`'))));
    }

    /**
     * Every `iam.*` key a guide names is a key of the configuration file.
     *
     * @return void
     */
    public function testEveryKeyTheGuidesNameExists(): void
    {
        $configuration = self::configuration();
        $unknown       = [];

        foreach (glob(self::root() . '/docs/guides/*.md') ?: [] as $guide) {

            preg_match_all('/`iam\.([a-z_]+(?:\.[a-z_]+)*)`/', (string) file_get_contents($guide), $keys);

            foreach ($keys[1] as $key) {
                if (Arr::has($configuration, $key)) {
                    continue;
                }

                $unknown[] = basename($guide) . ': iam.' . $key;
            }
        }

        self::assertSame([], array_values(array_unique($unknown)));
    }

    /**
     * The configuration file as the package ships it.
     *
     * @return array<array-key, mixed>
     */
    private static function configuration(): array
    {
        $configuration = require self::root() . '/config/iam.php';

        return is_array($configuration) ? $configuration : self::fail('The configuration file returns no array.');
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
