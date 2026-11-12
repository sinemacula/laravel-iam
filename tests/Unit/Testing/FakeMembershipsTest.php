<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing;

use Carbon\CarbonImmutable;
use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Contracts\Memberships;
use SineMacula\Laravel\Iam\Tenancy\Membership;
use SineMacula\Laravel\Iam\Testing\FakeMemberships;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Sso\PlainIdentity;

/**
 * Unit tests for the fake memberships.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FakeMemberships::class)]
final class FakeMembershipsTest extends TestCase
{
    /** @var string The tenant the member belongs to. */
    private const string TENANT = 'tenant-1';

    /** @var ?\SineMacula\Laravel\Iam\Testing\FakeMemberships The fake under test. */
    private ?FakeMemberships $fake = null;

    /**
     * An identity never granted anything holds a complete, empty set.
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
     * A grant of a tenant already held replaces its membership.
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
     * Identities of two kinds with the same identifier are two identities.
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
     * An identity the fake fails for throws the failure given, or its own.
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
     * An identity with no usable identifier is refused.
     *
     * @return void
     */
    public function testAnIdentityOfNoIdentifierIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->fake()->of(new Person);
    }

    /**
     * `fake()` binds a fresh fake as the memberships.
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
