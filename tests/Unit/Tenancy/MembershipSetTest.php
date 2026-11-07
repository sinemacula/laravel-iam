<?php

declare(strict_types = 1);

namespace Tests\Unit\Tenancy;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Tenancy\Membership;
use SineMacula\Laravel\Iam\Tenancy\MembershipSet;

/**
 * Unit tests for an identity's memberships (IAM-7.4): a set finds the
 * membership of exactly a tenant, tells whether it reaches beyond one, is
 * complete unless marked incomplete, and holds each tenant's membership, and a
 * platform principal, once.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MembershipSet::class)]
final class MembershipSetTest extends TestCase
{
    /**
     * The membership of exactly the tenant asked is found, byte for byte, and
     * none for a tenant the set holds no membership of.
     *
     * @return void
     */
    public function testTheMembershipOfExactlyTheTenantIsFound(): void
    {
        $first  = Membership::of('tenant-1', CarbonImmutable::now());
        $second = Membership::of('tenant-2');
        $set    = MembershipSet::complete($first, $second, Membership::platform());

        self::assertSame($first, $set->in('tenant-1'));
        self::assertSame($second, $set->in('tenant-2'));
        self::assertNull($set->in('Tenant-1'));
        self::assertNull($set->in('tenant-3'));
        self::assertSame([$first, $second], array_slice($set->memberships, 0, 2));
    }

    /**
     * A set is complete unless marked incomplete, and an empty one holds no
     * membership of any tenant.
     *
     * @return void
     */
    public function testASetIsCompleteUnlessMarkedIncomplete(): void
    {
        self::assertTrue(MembershipSet::complete()->isComplete());
        self::assertTrue((new MembershipSet([]))->isComplete());
        self::assertFalse(MembershipSet::incomplete(Membership::of('tenant-1'))->isComplete());
        self::assertFalse((new MembershipSet([], false))->isComplete());
        self::assertNull(MembershipSet::complete()->in('tenant-1'));
    }

    /**
     * Rows of `[memberships, reaches beyond tenant-1]`.
     *
     * @return iterable<string, array{0: list<\SineMacula\Laravel\Iam\Tenancy\Membership>, 1: bool}>
     */
    public static function provideReaches(): iterable
    {
        yield 'none' => [[], false];

        yield 'the tenant alone' => [[Membership::of('tenant-1')], false];

        yield 'another tenant too' => [[Membership::of('tenant-1'), Membership::of('tenant-2')], true];

        yield 'another tenant alone' => [[Membership::of('tenant-2')], true];

        yield 'a platform principal' => [[Membership::of('tenant-1'), Membership::platform()], true];

        yield 'the tenant in another case' => [[Membership::of('Tenant-1')], true];
    }

    /**
     * A set reaches beyond a tenant when it holds a platform principal or a
     * membership of any other tenant, whether accepted or not.
     *
     * @param  list<\SineMacula\Laravel\Iam\Tenancy\Membership>  $memberships
     * @param  bool  $reaches
     * @return void
     */
    #[DataProvider('provideReaches')]
    public function testASetReachesBeyondATenantThroughAnyOtherMembership(array $memberships, bool $reaches): void
    {
        self::assertSame($reaches, (new MembershipSet($memberships))->reachesBeyond('tenant-1'));
        self::assertSame($reaches, (new MembershipSet($memberships, false))->reachesBeyond('tenant-1'));
    }

    /**
     * Rows of `[memberships]`: each set holding a tenant's membership, or a
     * platform principal, twice.
     *
     * @return iterable<string, array{0: list<\SineMacula\Laravel\Iam\Tenancy\Membership>}>
     */
    public static function provideDuplicates(): iterable
    {
        yield 'a tenant twice' => [[Membership::of('tenant-1'), Membership::of('tenant-1', CarbonImmutable::now())]];

        yield 'two platform principals' => [[Membership::platform(), Membership::platform()]];
    }

    /**
     * A set holding a tenant's membership, or a platform principal, twice is
     * refused, since which of the two answered would be a guess.
     *
     * @param  list<\SineMacula\Laravel\Iam\Tenancy\Membership>  $memberships
     * @return void
     */
    #[DataProvider('provideDuplicates')]
    public function testASetHoldsEachMembershipOnce(array $memberships): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new MembershipSet($memberships);
    }

    /**
     * Memberships handed in by name are kept as a list, in the order given.
     *
     * @return void
     */
    public function testMembershipsHandedInByNameAreKeptAsAList(): void
    {
        $first  = Membership::of('tenant-1');
        $second = Membership::of('tenant-2');

        self::assertSame([$first, $second], MembershipSet::complete(...['first' => $first, 'second' => $second])->memberships);
        self::assertSame([$first, $second], MembershipSet::incomplete(...['first' => $first, 'second' => $second])->memberships);
    }

    /**
     * A membership of a tenant whose id looks like a number is told apart from
     * a platform principal and from another tenant's.
     *
     * @return void
     */
    public function testANumericTenantIsItsOwnTenant(): void
    {
        $set = MembershipSet::complete(Membership::of('0'), Membership::of('00'), Membership::platform());

        self::assertTrue($set->in('0')?->isOf('0'));
        self::assertTrue($set->in('00')?->isOf('00'));
        self::assertTrue($set->reachesBeyond('0'));
    }
}
