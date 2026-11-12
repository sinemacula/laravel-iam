<?php

declare(strict_types = 1);

namespace Tests\Unit\Provisioning;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Contracts\GroupResync;
use SineMacula\Laravel\Iam\Provisioning\ConfiguredGroupMapping;
use SineMacula\Laravel\Iam\Provisioning\GroupSettings;
use SineMacula\Laravel\Iam\Testing\FakeGroupMapping;

/**
 * Unit tests for finding the application's group mapping and re-sync.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GroupSettings::class)]
final class GroupSettingsTest extends TestCase
{
    /**
     * The map's key is the shipped configuration's.
     *
     * @return void
     */
    public function testTheMapKeyIsTheShippedConfigurations(): void
    {
        self::assertSame('iam.provisioning.groups.map', GroupSettings::MAP);
    }

    /**
     * Rows of `[map]`: maps that map no group.
     *
     * @return iterable<string, array{0: ?array<string, string>}>
     */
    public static function provideEmptyMaps(): iterable
    {
        yield 'none' => [null];

        yield 'empty' => [[]];
    }

    /**
     * With nothing configured nothing is mapped.
     *
     * @param  ?array<string, string>  $map
     * @return void
     */
    #[DataProvider('provideEmptyMaps')]
    public function testWithNothingConfiguredNothingIsMapped(?array $map): void
    {
        $settings = self::settings(new Container, ['map' => $map]);

        self::assertNull($settings->mapping());
        self::assertNull($settings->resync());
    }

    /**
     * With groups mapped and no mapping bound, the map is the mapping.
     *
     * @return void
     */
    public function testTheMapIsTheMappingWhileNothingElseIs(): void
    {
        self::assertInstanceOf(ConfiguredGroupMapping::class, self::settings(new Container, ['map' => ['finance' => 'invoices.viewer']])->mapping());
    }

    /**
     * A bound mapping wins over the map.
     *
     * @return void
     */
    public function testABoundMappingWinsOverTheMap(): void
    {
        $container = new Container;
        $mapping   = FakeGroupMapping::fake($container);

        self::assertSame($mapping, self::settings($container, ['map' => ['finance' => 'invoices.viewer']])->mapping());
    }

    /**
     * The re-sync bound when asked is the one answered.
     *
     * @return void
     */
    public function testTheBoundReSyncIsAnswered(): void
    {
        $container = new Container;
        $settings  = self::settings($container, []);
        $resync    = \Mockery::mock(GroupResync::class);

        $container->instance(GroupResync::class, $resync);

        self::assertSame($resync, $settings->resync());
    }

    /**
     * The settings over the groups' configuration given.
     *
     * @param  \Illuminate\Container\Container  $container
     * @param  array<string, mixed>  $groups
     * @return \SineMacula\Laravel\Iam\Provisioning\GroupSettings
     */
    private static function settings(Container $container, array $groups): GroupSettings
    {
        return new GroupSettings($container, new Repository(['iam' => ['provisioning' => ['groups' => $groups]]]));
    }
}
