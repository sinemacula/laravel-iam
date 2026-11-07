<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Testing\Seams;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Iam\Tenancy\Membership;

/**
 * What every application's memberships must guarantee, as assertions (IAM-7.4):
 * they answer an identity the same way every time while nothing changes; a
 * membership the person accepted is answered with the time the person accepted
 * it, and one an administrator created that the person never accepted with
 * none; a revoked membership is no current one; a set that cannot be read in
 * full is marked incomplete, or the read throws, never answered as complete;
 * and a set answered complete holds every principal the identity holds, its
 * memberships of other tenants and its platform principal wherever the
 * application keeps each.
 *
 * SSO counts a membership for linking by a verified domain only when it was
 * accepted before the domain's verification, so a creation time answered as an
 * acceptance would let a tenant that claims a domain add people and capture
 * them; and SSO takes a complete set as every principal the person holds, so a
 * partial one answered as complete could place someone within a tenant who
 * reaches beyond it. Each assertion takes the question as a closure, so a test
 * case asks it as the application's own memberships would be asked.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
abstract class MembershipsContract
{
    /**
     * Asking about the identity twice, with nothing changed in between, answers
     * the same memberships, as complete or as incomplete.
     *
     * @param  \Closure(): \SineMacula\Laravel\Iam\Tenancy\MembershipSet  $ask
     * @return void
     */
    public static function assertDeterministic(\Closure $ask): void
    {
        $first  = $ask();
        $second = $ask();

        Assert::assertEquals($first->memberships, $second->memberships, 'The memberships answered the same identity differently with nothing changed.');
        Assert::assertSame($first->isComplete(), $second->isComplete(), 'The memberships answered the same identity complete once and incomplete once with nothing changed.');
    }

    /**
     * The identity holds a membership of the tenant, accepted at exactly the
     * time the person accepted it.
     *
     * @param  \Closure(): \SineMacula\Laravel\Iam\Tenancy\MembershipSet  $ask
     * @param  string  $tenantId
     * @param  \Carbon\CarbonImmutable  $acceptedAt
     * @return void
     */
    public static function assertAnswersThePersonsAcceptance(\Closure $ask, string $tenantId, CarbonImmutable $acceptedAt): void
    {
        $membership = $ask()->in($tenantId);

        Assert::assertNotNull($membership, 'The memberships did not answer the identity\'s membership of the tenant.');
        Assert::assertNotNull($membership->acceptedAt, 'The memberships answered a membership the person accepted with no acceptance time.');
        Assert::assertTrue($acceptedAt->equalTo($membership->acceptedAt), 'The memberships answered another time than the person\'s acceptance.');
    }

    /**
     * A membership of the tenant an administrator created, which the person
     * never accepted, is answered with no acceptance time, or not at all.
     *
     * @param  \Closure(): \SineMacula\Laravel\Iam\Tenancy\MembershipSet  $ask
     * @param  string  $tenantId
     * @return void
     */
    public static function assertAnAdministratorsMembershipIsNotAccepted(\Closure $ask, string $tenantId): void
    {
        $membership = $ask()->in($tenantId);

        Assert::assertTrue($membership === null || $membership->acceptedAt === null, 'The memberships answered an acceptance time for a membership the person never accepted.');
    }

    /**
     * Once the identity's membership of the tenant is revoked, it is no longer
     * answered.
     *
     * @param  \Closure(): \SineMacula\Laravel\Iam\Tenancy\MembershipSet  $ask
     * @param  \Closure(): void  $revoke
     * @param  string  $tenantId
     * @return void
     */
    public static function assertARevokedMembershipIsNotCurrent(\Closure $ask, \Closure $revoke, string $tenantId): void
    {
        Assert::assertNotNull($ask()->in($tenantId), 'The memberships did not answer the membership before it was revoked.');

        $revoke();

        Assert::assertNull($ask()->in($tenantId), 'The memberships still answered a revoked membership.');
    }

    /**
     * Asking about an identity that holds principals beyond the tenant (a
     * membership of the other tenant given, a platform principal, or both)
     * throws, or answers a set marked incomplete, or answers a complete set
     * holding each of them, which therefore reaches beyond the tenant: never a
     * complete set that leaves one out, which SSO would take for every
     * principal the person holds and could place within a tenant someone who
     * reaches beyond it.
     *
     * @param  \Closure(): \SineMacula\Laravel\Iam\Tenancy\MembershipSet  $ask
     * @param  string  $tenantId
     * @param  ?string  $otherTenantId
     * @param  bool  $platform
     * @return void
     */
    public static function assertAnswersEveryPrincipal(\Closure $ask, string $tenantId, ?string $otherTenantId, bool $platform): void
    {
        Assert::assertTrue($otherTenantId !== null || $platform, 'The test case names no principal the identity holds beyond the tenant.');

        try {
            $set = $ask();
        } catch (\Throwable) {
            return;
        }

        if (!$set->isComplete()) {
            return;
        }

        $platforms = array_filter($set->memberships, static fn (Membership $membership): bool => $membership->isPlatform());

        Assert::assertTrue($set->reachesBeyond($tenantId), 'The memberships answered a complete set that does not reach beyond the tenant for an identity that does.');
        $otherHeld = $otherTenantId === null || $set->in($otherTenantId) !== null;

        Assert::assertTrue($otherHeld, 'The memberships answered a complete set without the identity\'s membership of another tenant.');
        Assert::assertTrue(!$platform || $platforms !== [], 'The memberships answered a complete set without the identity\'s platform principal.');
    }

    /**
     * Asking about an identity whose memberships cannot all be read throws, or
     * answers a set marked incomplete, never a complete one.
     *
     * @param  \Closure(): \SineMacula\Laravel\Iam\Tenancy\MembershipSet  $ask
     * @return void
     */
    public static function assertNeverCompleteWhenUnreadable(\Closure $ask): void
    {
        try {
            $set = $ask();
        } catch (\Throwable) {
            return;
        }

        Assert::assertFalse($set->isComplete(), 'The memberships answered a set they could not read in full as complete.');
    }
}
