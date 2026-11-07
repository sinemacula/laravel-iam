<?php

declare(strict_types = 1);

namespace Tests\Unit\Tenancy;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Tenancy\Membership;

/**
 * Unit tests for one membership (IAM-7.4): a membership of a tenant, or a
 * platform principal of none, accepted by the person at a time or not yet; it
 * is of exactly its tenant, byte for byte; and a blank tenant id is refused.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Membership::class)]
final class MembershipTest extends TestCase
{
    /**
     * A membership of a tenant the person accepted keeps its tenant and the
     * time, is of that tenant alone, and is no platform principal.
     *
     * @return void
     */
    public function testAnAcceptedMembershipOfATenant(): void
    {
        $acceptedAt = CarbonImmutable::parse('2026-01-01 09:00:00');
        $membership = Membership::of('tenant-1', $acceptedAt);

        self::assertSame('tenant-1', $membership->tenantId);
        self::assertSame($acceptedAt, $membership->acceptedAt);
        self::assertTrue($membership->isAccepted());
        self::assertTrue($membership->isOf('tenant-1'));
        self::assertFalse($membership->isOf('Tenant-1'));
        self::assertFalse($membership->isOf('tenant-1 '));
        self::assertFalse($membership->isPlatform());
    }

    /**
     * A membership the person has not accepted has no acceptance time.
     *
     * @return void
     */
    public function testAMembershipNotAcceptedHasNoAcceptanceTime(): void
    {
        $membership = Membership::of('tenant-1');

        self::assertNull($membership->acceptedAt);
        self::assertFalse($membership->isAccepted());
    }

    /**
     * A platform principal belongs to no tenant, and is of none.
     *
     * @return void
     */
    public function testAPlatformPrincipalIsOfNoTenant(): void
    {
        $membership = Membership::platform(CarbonImmutable::now());

        self::assertNull($membership->tenantId);
        self::assertTrue($membership->isPlatform());
        self::assertTrue($membership->isAccepted());
        self::assertFalse($membership->isOf(''));
        self::assertFalse(Membership::platform()->isAccepted());
    }

    /**
     * Rows of `[tenant id]`: each blank id a membership is refused for.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideBlankTenants(): iterable
    {
        yield 'empty' => [''];

        yield 'spaces' => ['   '];
    }

    /**
     * A blank tenant id is refused, so a platform principal is never named by
     * one.
     *
     * @param  string  $tenantId
     * @return void
     */
    #[DataProvider('provideBlankTenants')]
    public function testABlankTenantIsRefused(string $tenantId): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new Membership($tenantId);
    }
}
