<?php

declare(strict_types = 1);

namespace Tests\Unit\Provisioning;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Iam\Authorization\Translation\TenantTranslator;
use SineMacula\Laravel\Iam\Contracts\GroupResync;
use SineMacula\Laravel\Iam\Exceptions\GroupMappingMisconfiguredException;
use SineMacula\Laravel\Iam\Provisioning\ConfiguredGroupMapping;
use SineMacula\Laravel\Iam\Provisioning\GroupGrants;
use SineMacula\Laravel\Iam\Provisioning\GroupSettings;
use SineMacula\Laravel\Iam\Provisioning\MappedGroupResync;
use SineMacula\Laravel\Iam\Tenancy\TenantReferences;
use SineMacula\Laravel\Iam\Testing\FakeGroupMapping;

/**
 * Unit tests for finding the application's group mapping and re-sync (IAM-7.2):
 * a binding of either contract wins over the class named, the map is the
 * mapping while nothing else is, neither maps or re-syncs nothing, a name or a
 * binding that is no implementation throws, and the shipped re-sync refuses
 * rather than revoke every role for want of a mapping.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GroupSettings::class)]
#[CoversClass(MappedGroupResync::class)]
final class GroupSettingsTest extends TestCase
{
    /**
     * The keys are the shipped configuration's.
     *
     * @return void
     */
    public function testTheKeysAreTheShippedConfigurations(): void
    {
        self::assertSame('iam.provisioning.groups.mapping', GroupSettings::MAPPING);
        self::assertSame('iam.provisioning.groups.map', GroupSettings::MAP);
        self::assertSame('iam.provisioning.groups.resync', GroupSettings::RESYNC);
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
     * With no mapping bound or named and no group mapped, groups map to
     * nothing, and nothing is re-synced.
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
     * With groups mapped and no mapping bound or named, the map is the mapping.
     *
     * @return void
     */
    public function testTheMapIsTheMappingWhileNothingElseIs(): void
    {
        self::assertInstanceOf(ConfiguredGroupMapping::class, self::settings(new Container, ['map' => ['finance' => 'invoices.viewer']])->mapping());
    }

    /**
     * A mapping and a re-sync named are built from the container, and one bound
     * wins over the one named.
     *
     * @return void
     */
    public function testABindingWinsOverTheClassNamed(): void
    {
        $container = new Container;
        $settings  = self::settings($container, ['mapping' => FakeGroupMapping::class, 'map' => ['finance' => 'invoices.viewer'], 'resync' => MappedGroupResync::class]);

        $container->instance(GroupSettings::class, $settings);
        $container->instance(GroupGrants::class, new GroupGrants($container, new TenantTranslator(new TenantReferences($container))));

        self::assertInstanceOf(FakeGroupMapping::class, $settings->mapping());
        self::assertInstanceOf(MappedGroupResync::class, $settings->resync());

        $mapping = FakeGroupMapping::fake($container);
        $resync  = \Mockery::mock(GroupResync::class);

        $container->instance(GroupResync::class, $resync);

        self::assertSame($mapping, $settings->mapping());
        self::assertSame($resync, $settings->resync());
    }

    /**
     * Rows of `[key, value]`: a mapping or re-sync named by what is no
     * implementation.
     *
     * @return iterable<string, array{0: string, 1: mixed}>
     */
    public static function provideMisconfigurations(): iterable
    {
        yield 'a mapping that is no class' => ['mapping', true];

        yield 'a mapping of another contract' => ['mapping', MappedGroupResync::class];

        yield 'a re-sync that is no class' => ['resync', 7];

        yield 'a re-sync of another contract' => ['resync', FakeGroupMapping::class];
    }

    /**
     * A mapping or re-sync named by what is no implementation throws.
     *
     * @param  string  $key
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideMisconfigurations')]
    public function testAMisconfigurationThrows(string $key, mixed $value): void
    {
        $settings = self::settings(new Container, [$key => $value]);

        $this->expectException(GroupMappingMisconfiguredException::class);

        $key === 'mapping' ? $settings->mapping() : $settings->resync();
    }

    /**
     * The shipped re-sync refuses with no mapping, before anything is written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheShippedReSyncRefusesWithNoMapping(): void
    {
        $container = new Container;
        $resync    = new MappedGroupResync(self::settings($container, []), new GroupGrants($container, new TenantTranslator(new TenantReferences($container))));

        $this->expectException(GroupMappingMisconfiguredException::class);
        $this->expectExceptionMessage(GroupSettings::MAPPING);

        $resync->resync(\Mockery::mock(Identity::class), 'connection-1', 'tenant-1', ['finance']);
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
