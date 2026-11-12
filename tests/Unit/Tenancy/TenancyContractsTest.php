<?php

declare(strict_types = 1);

namespace Tests\Unit\Tenancy;

use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Contracts\Memberships;
use SineMacula\Laravel\Iam\Tenancy\TenancyContracts;
use SineMacula\Laravel\Iam\Testing\FakeMemberships;

/**
 * Unit tests for finding the application's memberships.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TenancyContracts::class)]
final class TenancyContractsTest extends TestCase
{
    /**
     * Unbound memberships throw rather than answer none.
     *
     * @return void
     */
    public function testUnboundMembershipsThrow(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(Memberships::class . ' is unbound; bind an implementation of your own to it.');

        (new TenancyContracts(new Container))->memberships();
    }

    /**
     * The memberships bound when asked are the ones answered.
     *
     * @return void
     */
    public function testTheBoundMembershipsAreAsked(): void
    {
        $container = new Container;
        $contracts = new TenancyContracts($container);

        $container->bind(Memberships::class, FakeMemberships::class);

        self::assertInstanceOf(FakeMemberships::class, $contracts->memberships());
        self::assertNotSame($contracts->memberships(), $contracts->memberships());

        $memberships = FakeMemberships::fake($container);

        self::assertSame($memberships, $contracts->memberships());
    }
}
