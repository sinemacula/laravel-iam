<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Testing\Seams\Concerns;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Iam\Contracts\Memberships;
use SineMacula\Laravel\Iam\Testing\Seams\MembershipsContract;

/**
 * The `Memberships` contract kit (IAM-7.4): the memberships answer an identity
 * the same way while nothing changes, answer a membership with the time the
 * person accepted it and one an administrator created with none, drop a revoked
 * membership, never answer a set they cannot read in full as complete, and
 * never answer as complete a set that leaves out a principal the identity holds
 * elsewhere: a membership of another tenant or a platform principal.
 *
 * A test case proves the application's memberships by using this trait and
 * implementing the hooks against its own data: a member of a tenant and when
 * the person accepted the membership, an identity an administrator added to
 * that tenant who never accepted, a way to revoke a membership (as an
 * administrator would), an identity whose memberships cannot all be read, and
 * an identity that holds the tenant's membership and principals beyond it, a
 * membership of another tenant, a platform principal or both, each stored
 * wherever the application keeps it. Each check delegates to
 * `MembershipsContract`.
 *
 * The kit asks on one connection, so it cannot prove the membership guard
 * `Contracts\Memberships` requires: that asking takes a lock held until the
 * asking transaction ends, which every writer that revokes, expires or narrows
 * a membership takes too, so a revocation made while a redemption that read the
 * membership is open waits for it to commit. Prove that with a race of the
 * application's own, on its database at the isolation level it runs at: read
 * the memberships inside a transaction, revoke on a second connection with a
 * short lock timeout, and expect the revocation to wait.
 *
 * @phpstan-require-extends \PHPUnit\Framework\TestCase
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
trait MembershipsTests
{
    /**
     * The same identity is answered the same way while nothing changes.
     *
     * @return void
     */
    public function testMembershipsAreDeterministic(): void
    {
        $memberships = $this->memberships();
        $identity    = $this->memberIdentity();

        MembershipsContract::assertDeterministic(static fn () => $memberships->of($identity));
    }

    /**
     * A membership the person accepted is answered with the time they did.
     *
     * @return void
     */
    public function testMembershipsAnswerThePersonsAcceptance(): void
    {
        $memberships = $this->memberships();
        $identity    = $this->memberIdentity();

        MembershipsContract::assertAnswersThePersonsAcceptance(static fn () => $memberships->of($identity), $this->membershipTenant(), $this->membershipAcceptedAt());
    }

    /**
     * A membership an administrator created, which the person never accepted,
     * is answered with no acceptance time.
     *
     * @return void
     */
    public function testMembershipsAnswerNoAcceptanceForAnAdministratorsMembership(): void
    {
        $memberships = $this->memberships();
        $identity    = $this->invitedIdentity();

        MembershipsContract::assertAnAdministratorsMembershipIsNotAccepted(static fn () => $memberships->of($identity), $this->membershipTenant());
    }

    /**
     * A revoked membership is no longer answered.
     *
     * @return void
     */
    public function testMembershipsDropARevokedMembership(): void
    {
        $memberships = $this->memberships();
        $identity    = $this->memberIdentity();
        $tenantId    = $this->membershipTenant();

        MembershipsContract::assertARevokedMembershipIsNotCurrent(
            static fn () => $memberships->of($identity),
            fn () => $this->revokeMembership($identity, $tenantId),
            $tenantId,
        );
    }

    /**
     * An identity whose memberships cannot all be read is answered incomplete,
     * or the read throws.
     *
     * @return void
     */
    public function testMembershipsAreNeverCompleteWhenUnreadable(): void
    {
        $memberships = $this->memberships();
        $identity    = $this->partlyReadableIdentity();

        MembershipsContract::assertNeverCompleteWhenUnreadable(static fn () => $memberships->of($identity));
    }

    /**
     * An identity that holds principals beyond the tenant is answered with
     * every one of them, or incomplete, or the read throws.
     *
     * @return void
     */
    public function testMembershipsAnswerEveryPrincipal(): void
    {
        $memberships = $this->memberships();
        $identity    = $this->widelyHeldIdentity();

        MembershipsContract::assertAnswersEveryPrincipal(
            static fn () => $memberships->of($identity),
            $this->membershipTenant(),
            $this->otherMembershipTenant(),
            $this->holdsPlatformPrincipal(),
        );
    }

    /**
     * The memberships under test.
     *
     * @return \SineMacula\Laravel\Iam\Contracts\Memberships
     */
    abstract protected function memberships(): Memberships;

    /**
     * An identity holding a membership of the tenant, which the person
     * accepted.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     */
    abstract protected function memberIdentity(): Identity;

    /**
     * The tenant the member's membership is of.
     *
     * @return string
     */
    abstract protected function membershipTenant(): string;

    /**
     * When the person accepted the member's membership.
     *
     * @return \Carbon\CarbonImmutable
     */
    abstract protected function membershipAcceptedAt(): CarbonImmutable;

    /**
     * An identity an administrator added to the tenant, who never accepted.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     */
    abstract protected function invitedIdentity(): Identity;

    /**
     * Revoke the identity's membership of the tenant, as the application would.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $tenantId
     * @return void
     */
    abstract protected function revokeMembership(Identity $identity, string $tenantId): void;

    /**
     * An identity whose memberships cannot all be read.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     */
    abstract protected function partlyReadableIdentity(): Identity;

    /**
     * An identity that holds a membership of the tenant and principals beyond
     * it: a membership of `otherMembershipTenant()`, a platform principal
     * (`holdsPlatformPrincipal()`), or both, each stored wherever the
     * application keeps it.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     */
    abstract protected function widelyHeldIdentity(): Identity;

    /**
     * The other tenant the widely held identity is a member of, or `null` when
     * it holds no other tenant's membership (it then holds a platform
     * principal).
     *
     * @return ?string
     */
    abstract protected function otherMembershipTenant(): ?string;

    /**
     * Whether the widely held identity holds a platform principal.
     *
     * @return bool
     */
    abstract protected function holdsPlatformPrincipal(): bool;
}
