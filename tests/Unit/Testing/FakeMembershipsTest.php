<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing;

use Carbon\CarbonImmutable;
use Illuminate\Container\Container;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Iam\Contracts\Memberships;
use SineMacula\Laravel\Iam\Tenancy\Membership;
use SineMacula\Laravel\Iam\Tenancy\MembershipSet;
use SineMacula\Laravel\Iam\Testing\FakeMemberships;
use SineMacula\Laravel\Iam\Testing\Seams\Concerns\MembershipsTests;
use SineMacula\Laravel\Iam\Testing\Seams\MembershipsContract;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Sso\PlainIdentity;

/**
 * Proves the `Memberships` contract kit against this package's fake memberships
 * (IAM-7.4): the fake answers an identity the same way while nothing changes,
 * with the person's acceptance time or none, drops a revoked membership,
 * answers an identity marked incomplete as incomplete and answers every
 * principal an identity holds; and the kit's assertions fail memberships that
 * break any of those, a complete set leaving out a platform principal or
 * another tenant's membership among them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FakeMemberships::class)]
#[CoversClass(MembershipsContract::class)]
#[CoversTrait(MembershipsTests::class)]
final class FakeMembershipsTest extends TestCase
{
    use MembershipsTests;

    /** @var string The tenant the member belongs to. */
    private const string TENANT = 'tenant-1';

    /** @var string Another tenant the widely held identity belongs to. */
    private const string OTHER_TENANT = 'tenant-2';

    /** @var ?\SineMacula\Laravel\Iam\Testing\FakeMemberships The fake under test. */
    private ?FakeMemberships $fake = null;

    /**
     * An identity never granted anything holds no membership, in a complete
     * set, and the question is kept.
     *
     * @return void
     */
    public function testAnIdentityNeverGrantedAnythingHoldsNothing(): void
    {
        $set = $this->fake()->of(self::person(7));

        self::assertSame([], $set->memberships);
        self::assertTrue($set->isComplete());
        self::assertSame([['identity' => Person::class, 'id' => '7']], $this->fake()->asked());
    }

    /**
     * The same person read again is the same identity, another person is
     * another, and a grant of a tenant already held replaces its membership.
     *
     * @return void
     */
    public function testAGrantReplacesTheMembershipOfTheSameTenant(): void
    {
        $accepted = CarbonImmutable::parse('2026-02-01 10:00:00');
        $fake     = $this->fake()->grant(self::person(1), Membership::of(self::TENANT))->grant(self::person(1), Membership::platform());

        $fake->grant(self::person(1), Membership::of(self::TENANT, $accepted));

        $set = $fake->of(self::person(1));

        self::assertCount(2, $set->memberships);
        self::assertTrue(array_is_list($set->memberships));
        self::assertSame($accepted, $set->in(self::TENANT)?->acceptedAt);
        self::assertSame([], $fake->of(self::person(2))->memberships);

        $fake->revoke(self::person(1), null);

        self::assertFalse($fake->of(self::person(1))->reachesBeyond(self::TENANT));
    }

    /**
     * Identities of two kinds with the same identifier are two identities, and
     * marking one's set incomplete leaves the other's complete.
     *
     * @return void
     */
    public function testIdentitiesOfTwoKindsAreTwoIdentities(): void
    {
        $other = new PlainIdentity(['id' => 1]);
        $fake  = $this->fake()->grant(self::person(1), Membership::of(self::TENANT))->incomplete(self::person(1));

        self::assertSame([], $fake->of($other)->memberships);
        self::assertTrue($fake->of($other)->isComplete());
        self::assertFalse($fake->of(self::person(1))->isComplete());
        self::assertSame(['identity' => PlainIdentity::class, 'id' => '1'], $fake->asked()[0]);
    }

    /**
     * An identity the fake was told to fail for throws the failure given, or
     * one of its own.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailingIdentityThrows(): void
    {
        $failure = new \RuntimeException('Unreadable.');

        try {
            $this->fake()->failFor(self::person(1), $failure)->of(self::person(1));

            self::fail('The fake answered.');
        } catch (\RuntimeException $exception) {
            self::assertSame($failure, $exception);
        }

        $this->expectException(\RuntimeException::class);

        $this->fake()->failFor(self::person(2))->of(self::person(2));
    }

    /**
     * An identity with no identifier the fake can key its answers by is
     * refused.
     *
     * @return void
     */
    public function testAnIdentityOfNoIdentifierIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->fake()->of(new Person);
    }

    /**
     * `fake()` binds a fresh fake as the application's memberships, in the
     * container given or the global one.
     *
     * @return void
     */
    public function testFakeBindsAFreshFakeAsTheMemberships(): void
    {
        $container = new Container;
        $fake      = FakeMemberships::fake($container);

        self::assertSame($fake, $container->make(Memberships::class));

        $previous = Container::getInstance();

        try {
            Container::setInstance($global = new Container);

            $other = FakeMemberships::fake();

            self::assertSame($other, $global->make(FakeMemberships::MEMBERSHIPS));
            self::assertNotSame($fake, $other);
        } finally {
            Container::setInstance($previous);
        }
    }

    /**
     * The kit fails memberships that answer an identity differently with
     * nothing changed, in what they hold or in their completeness.
     *
     * @return void
     */
    public function testTheKitFailsAnAnswerThatDrifts(): void
    {
        self::assertDriftFails('answered the same identity differently', MembershipSet::complete(Membership::of(self::TENANT)), MembershipSet::complete());
        self::assertDriftFails('complete once and incomplete once', MembershipSet::complete(), MembershipSet::incomplete());
    }

    /**
     * The kit fails memberships that answer no membership, none accepted, or
     * another time than the person's acceptance.
     *
     * @return void
     */
    public function testTheKitFailsAnAnswerOtherThanThePersonsAcceptance(): void
    {
        $accepted = CarbonImmutable::parse('2026-02-01 10:00:00');

        foreach (
            [
                'did not answer the identity\'s membership'  => MembershipSet::complete(),
                'with no acceptance time'                    => MembershipSet::complete(Membership::of(self::TENANT)),
                'another time than the person\'s acceptance' => MembershipSet::complete(Membership::of(self::TENANT, $accepted->addSecond())),
            ] as $message => $answer
        ) {

            try {
                MembershipsContract::assertAnswersThePersonsAcceptance(static fn (): MembershipSet => $answer, self::TENANT, $accepted);

                self::fail('The kit passed.');
            } catch (AssertionFailedError $failure) {
                self::assertStringContainsString($message, $failure->getMessage());
            }
        }
    }

    /**
     * The kit fails memberships that answer an acceptance time for a membership
     * the person never accepted.
     *
     * @return void
     */
    public function testTheKitFailsAnAdministratorsTimeAnsweredAsAnAcceptance(): void
    {
        MembershipsContract::assertAnAdministratorsMembershipIsNotAccepted(static fn (): MembershipSet => MembershipSet::complete(), self::TENANT);
        MembershipsContract::assertAnAdministratorsMembershipIsNotAccepted(static fn (): MembershipSet => MembershipSet::complete(Membership::of(self::TENANT)), self::TENANT);

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('answered an acceptance time for a membership the person never accepted');

        $accepted = MembershipSet::complete(Membership::of(self::TENANT, CarbonImmutable::now()));

        MembershipsContract::assertAnAdministratorsMembershipIsNotAccepted(static fn (): MembershipSet => $accepted, self::TENANT);
    }

    /**
     * The kit fails memberships that still answer a revoked membership, or
     * never answered it at all.
     *
     * @return void
     */
    public function testTheKitFailsARevokedMembershipStillAnswered(): void
    {
        $held = static fn (): MembershipSet => MembershipSet::complete(Membership::of(self::TENANT));

        try {
            MembershipsContract::assertARevokedMembershipIsNotCurrent($held, static function (): void {}, self::TENANT);

            self::fail('The kit passed.');
        } catch (AssertionFailedError $failure) {
            self::assertStringContainsString('still answered a revoked membership', $failure->getMessage());
        }

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('did not answer the membership before it was revoked');

        MembershipsContract::assertARevokedMembershipIsNotCurrent(static fn (): MembershipSet => MembershipSet::complete(), static function (): void {}, self::TENANT);
    }

    /**
     * The kit fails memberships that answer a set they cannot read in full as
     * complete, and accepts one that throws.
     *
     * @return void
     */
    public function testTheKitFailsAnUnreadableSetAnsweredAsComplete(): void
    {
        $unreadable = $this->fake()->failFor(self::person(9));

        MembershipsContract::assertNeverCompleteWhenUnreadable(static fn (): MembershipSet => $unreadable->of(self::person(9)));

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('could not read in full as complete');

        MembershipsContract::assertNeverCompleteWhenUnreadable(static fn (): MembershipSet => MembershipSet::complete());
    }

    /**
     * The kit fails memberships that answer as complete a set leaving out a
     * principal the identity holds: one reaching nothing beyond the tenant, one
     * without the other tenant's membership, and one without the platform
     * principal, as memberships reading only their tenants' table would; and it
     * accepts a read that throws, a set marked incomplete, and a complete set
     * holding every principal.
     *
     * @return void
     *
     * @throws \RuntimeException
     */
    public function testTheKitFailsACompleteSetThatLeavesOutAPrincipal(): void
    {
        $member = Membership::of(self::TENANT, $this->membershipAcceptedAt());
        $other  = Membership::of(self::OTHER_TENANT);

        foreach (
            [
                'does not reach beyond the tenant'           => [MembershipSet::complete($member), self::OTHER_TENANT, true],
                'membership of another tenant'               => [MembershipSet::complete($member, Membership::platform()), self::OTHER_TENANT, true],
                'platform principal'                         => [MembershipSet::complete($member, $other), self::OTHER_TENANT, true],
                'names no principal the identity holds'      => [MembershipSet::complete($member, $other), null, false],
                'platform principal (no other tenant named)' => [MembershipSet::complete($member, $other), null, true],
            ] as $message => [$answer, $otherTenant, $platform]
        ) {

            try {
                MembershipsContract::assertAnswersEveryPrincipal(static fn (): MembershipSet => $answer, self::TENANT, $otherTenant, $platform);

                self::fail('The kit passed.');
            } catch (AssertionFailedError $failure) {
                self::assertStringContainsString(explode(' (', $message)[0], $failure->getMessage(), $message);
            }
        }

        $every = MembershipSet::complete($member, $other, Membership::platform());

        MembershipsContract::assertAnswersEveryPrincipal(static fn (): MembershipSet => throw new \RuntimeException('Unreadable.'), self::TENANT, self::OTHER_TENANT, true);
        MembershipsContract::assertAnswersEveryPrincipal(static fn (): MembershipSet => MembershipSet::incomplete($member), self::TENANT, self::OTHER_TENANT, true);
        MembershipsContract::assertAnswersEveryPrincipal(static fn (): MembershipSet => $every, self::TENANT, self::OTHER_TENANT, true);
        MembershipsContract::assertAnswersEveryPrincipal(static fn (): MembershipSet => MembershipSet::complete($member, $other), self::TENANT, self::OTHER_TENANT, false);
        MembershipsContract::assertAnswersEveryPrincipal(static fn (): MembershipSet => MembershipSet::complete($member, Membership::platform()), self::TENANT, null, true);
    }

    /**
     * The fake under test, with the member and the invited identity granted and
     * the partly readable one marked incomplete, and the widely held one
     * granted its tenant's membership, another tenant's and a platform
     * principal.
     *
     * @return \SineMacula\Laravel\Iam\Contracts\Memberships
     */
    #[\Override]
    protected function memberships(): Memberships
    {
        return $this->fake()
            ->grant($this->memberIdentity(), Membership::of(self::TENANT, $this->membershipAcceptedAt()))
            ->grant($this->invitedIdentity(), Membership::of(self::TENANT))
            ->grant($this->partlyReadableIdentity(), Membership::of(self::TENANT, $this->membershipAcceptedAt()))
            ->incomplete($this->partlyReadableIdentity())
            ->grant($this->widelyHeldIdentity(), Membership::of(self::TENANT, $this->membershipAcceptedAt()))
            ->grant($this->widelyHeldIdentity(), Membership::of(self::OTHER_TENANT, $this->membershipAcceptedAt()))
            ->grant($this->widelyHeldIdentity(), Membership::platform());
    }

    /**
     * The member.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     */
    #[\Override]
    protected function memberIdentity(): Identity
    {
        return self::person(1);
    }

    /**
     * The member's tenant.
     *
     * @return string
     */
    #[\Override]
    protected function membershipTenant(): string
    {
        return self::TENANT;
    }

    /**
     * When the member accepted.
     *
     * @return \Carbon\CarbonImmutable
     */
    #[\Override]
    protected function membershipAcceptedAt(): CarbonImmutable
    {
        return CarbonImmutable::parse('2026-01-15 08:30:00');
    }

    /**
     * The identity an administrator added, who never accepted.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     */
    #[\Override]
    protected function invitedIdentity(): Identity
    {
        return self::person(2);
    }

    /**
     * Revoke the membership in the fake.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $tenantId
     * @return void
     */
    #[\Override]
    protected function revokeMembership(Identity $identity, string $tenantId): void
    {
        $this->fake()->revoke($identity, $tenantId);
    }

    /**
     * The identity whose set is marked incomplete.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     */
    #[\Override]
    protected function partlyReadableIdentity(): Identity
    {
        return self::person(3);
    }

    /**
     * The identity that also holds another tenant's membership and a platform
     * principal.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     */
    #[\Override]
    protected function widelyHeldIdentity(): Identity
    {
        return self::person(4);
    }

    /**
     * The other tenant the widely held identity is a member of.
     *
     * @return string
     */
    #[\Override]
    protected function otherMembershipTenant(): string
    {
        return self::OTHER_TENANT;
    }

    /**
     * The widely held identity holds a platform principal.
     *
     * @return bool
     */
    #[\Override]
    protected function holdsPlatformPrincipal(): bool
    {
        return true;
    }

    /**
     * Assert the kit fails memberships answering the two sets given in turn as
     * the same identity's, with the message given.
     *
     * @param  string  $message
     * @param  \SineMacula\Laravel\Iam\Tenancy\MembershipSet  $first
     * @param  \SineMacula\Laravel\Iam\Tenancy\MembershipSet  $second
     * @return void
     */
    private static function assertDriftFails(string $message, MembershipSet $first, MembershipSet $second): void
    {
        try {
            MembershipsContract::assertDeterministic(self::answers($first, $second));

            self::fail('The kit passed.');
        } catch (AssertionFailedError $failure) {
            self::assertStringContainsString($message, $failure->getMessage());
        }
    }

    /**
     * A question that answers each set given in turn.
     *
     * @param  \SineMacula\Laravel\Iam\Tenancy\MembershipSet  ...$answers
     * @return \Closure(): \SineMacula\Laravel\Iam\Tenancy\MembershipSet
     */
    private static function answers(MembershipSet ...$answers): \Closure
    {
        return static function () use (&$answers): MembershipSet {
            return array_shift($answers) ?? self::fail('Asked too often.');
        };
    }

    /**
     * A person of the id given, never stored.
     *
     * @param  int  $id
     * @return \Tests\Fixtures\Models\Person
     */
    private static function person(int $id): Person
    {
        return (new Person)->forceFill(['id' => $id]);
    }

    /**
     * The fake under test, made once per test.
     *
     * @return \SineMacula\Laravel\Iam\Testing\FakeMemberships
     */
    private function fake(): FakeMemberships
    {
        return $this->fake ??= new FakeMemberships;
    }
}
