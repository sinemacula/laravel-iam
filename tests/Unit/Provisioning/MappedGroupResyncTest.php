<?php

declare(strict_types = 1);

namespace Tests\Unit\Provisioning;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Iam\Authorization\Translation\TenantTranslator;
use SineMacula\Laravel\Iam\Contracts\GroupMapping;
use SineMacula\Laravel\Iam\Provisioning\GroupGrants;
use SineMacula\Laravel\Iam\Provisioning\GroupSettings;
use SineMacula\Laravel\Iam\Provisioning\MappedGroupResync;
use SineMacula\Laravel\Iam\Tenancy\TenantReferences;
use SineMacula\Laravel\Iam\Testing\FakeGroupMapping;

/**
 * Unit tests for the shipped group re-sync (IAM-7.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MappedGroupResync::class)]
final class MappedGroupResyncTest extends TestCase
{
    /**
     * With no mapping it refuses before anything is written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testItRefusesWithNoMapping(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(GroupMapping::class . ' is unbound and iam.provisioning.groups.map maps no group; a re-sync without a mapping would revoke every role.');

        self::resync(new Container)->resync(\Mockery::mock(Identity::class), 'connection-1', 'tenant-1', ['finance']);
    }

    /**
     * It asks the bound mapping.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testItAsksTheBoundMapping(): void
    {
        $container = new Container;
        $refusal   = new \RuntimeException('Refused.');

        FakeGroupMapping::fake($container)->refuse($refusal);

        $this->expectExceptionObject($refusal);

        self::resync($container)->resync(\Mockery::mock(Identity::class), 'connection-1', 'tenant-1', ['finance']);
    }

    /**
     * The re-sync over the container given.
     *
     * @param  \Illuminate\Container\Container  $container
     * @return \SineMacula\Laravel\Iam\Provisioning\MappedGroupResync
     */
    private static function resync(Container $container): MappedGroupResync
    {
        return new MappedGroupResync(new GroupSettings($container, new Repository), new GroupGrants($container, new TenantTranslator(new TenantReferences($container))));
    }
}
