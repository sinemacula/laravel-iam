<?php

declare(strict_types = 1);

namespace Tests\Unit\Audit;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Audit\AuditSettings;

/**
 * Unit tests for the mappers' switch and audit-log's `require_registered` rule.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuditSettings::class)]
final class AuditSettingsTest extends TestCase
{
    /**
     * The switch reads the shipped `audit.mappers` key, which is on by default.
     *
     * @return void
     */
    public function testTheKeyIsTheShippedConfigurations(): void
    {
        $shipped = require dirname(__DIR__, 3) . '/config/iam.php';

        self::assertIsArray($shipped);
        self::assertSame('iam.audit.mappers', AuditSettings::MAPPERS);
        self::assertArrayHasKey('audit', $shipped);
        self::assertIsArray($shipped['audit']);
        self::assertArrayHasKey('mappers', $shipped['audit']);
        self::assertTrue($shipped['audit']['mappers']);
        self::assertTrue((new AuditSettings(new Repository(['iam' => $shipped])))->mapsEvents());

        $shipped['audit']['mappers'] = false;

        self::assertFalse((new AuditSettings(new Repository(['iam' => $shipped])))->mapsEvents());
    }

    /**
     * Rows of `[value, on]` the switch may hold.
     *
     * @return iterable<string, array{0: mixed, 1: bool}>
     */
    public static function provideSwitches(): iterable
    {
        yield 'unset' => [null, true];

        yield 'empty' => ['', true];

        yield 'true' => [true, true];

        yield 'one' => ['1', true];

        yield 'on' => ['on', true];

        yield 'unrecognised' => ['maybe', true];

        yield 'false' => [false, false];

        yield 'false as text' => ['false', false];

        yield 'zero' => ['0', false];

        yield 'off' => ['off', false];

        yield 'no' => ['no', false];
    }

    /**
     * The switch is off only for a value that says off.
     *
     * @param  mixed  $value
     * @param  bool  $on
     * @return void
     */
    #[DataProvider('provideSwitches')]
    public function testTheSwitchIsOffOnlyWhenItSaysSo(mixed $value, bool $on): void
    {
        $settings = new AuditSettings(new Repository(['iam' => ['audit' => ['mappers' => $value]]]));

        self::assertSame($on, $settings->mapsEvents());
    }

    /**
     * Rows of `[value, on]` audit-log's rule may hold.
     *
     * @return iterable<string, array{0: mixed, 1: bool}>
     */
    public static function provideRequireRegistered(): iterable
    {
        yield 'true' => [true, true];

        yield 'false' => [false, false];

        yield 'true as text' => ['true', false];

        yield 'one' => [1, false];

        yield 'null' => [null, false];
    }

    /**
     * Audit-log's rule is on only while it is `true`.
     *
     * @param  mixed  $value
     * @param  bool  $on
     * @return void
     */
    #[DataProvider('provideRequireRegistered')]
    public function testUnregisteredCodesAreRefusedOnlyWhileTheRuleIsTrue(mixed $value, bool $on): void
    {
        $settings = new AuditSettings(new Repository(['audit-log' => ['definitions' => ['require_registered' => $value]]]));

        self::assertSame('audit-log.definitions.require_registered', AuditSettings::REQUIRE_REGISTERED);
        self::assertSame($on, $settings->refusesUnregisteredCodes());
    }

    /**
     * Unset, the rule is off, and it is read when asked.
     *
     * @return void
     */
    public function testTheRuleIsReadWhenAsked(): void
    {
        $config   = new Repository([]);
        $settings = new AuditSettings($config);

        self::assertFalse($settings->refusesUnregisteredCodes());

        $config->set(AuditSettings::REQUIRE_REGISTERED, true);

        self::assertTrue($settings->refusesUnregisteredCodes());
    }
}
