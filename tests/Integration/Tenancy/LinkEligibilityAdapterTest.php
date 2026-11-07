<?php

declare(strict_types = 1);

namespace Tests\Integration\Tenancy;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Tenancy\LinkEligibilityAdapter;
use SineMacula\Laravel\Iam\Tenancy\Membership;
use SineMacula\Laravel\Iam\Testing\FakeMemberships;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\Enums\LinkEligibilityVerdict;
use SineMacula\Laravel\Sso\Models\Connection;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * Integration tests for SSO's link eligibility, answered from the
 * application's memberships (IAM-7.4): an identity may link through a
 * connection only by a membership of exactly the connection's tenant that the
 * person accepted; an invitation not taken up, another tenant's membership, a
 * platform principal or none makes it ineligible; an incomplete set answers
 * the membership it holds; and an identity that cannot be resolved, or
 * memberships that cannot be read, throw inside SSO's transaction.
 *
 * The scenarios run at the connection's own level on every engine, then at READ
 * COMMITTED and REPEATABLE READ on MySQL and PostgreSQL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LinkEligibilityAdapter::class)]
final class LinkEligibilityAdapterTest extends TestCase
{
    use MigratesMembers, RunsAtIsolationLevels, SignsInPeople;

    /** @var string The connection's tenant. */
    private const string TENANT = 'tenant-1';

    /**
     * A member of the connection's tenant, by a membership the person accepted,
     * is eligible, inside SSO's transaction.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAnAcceptedMemberOfTheConnectionsTenantIsEligible(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person = $this->createPerson();

        FakeMemberships::fake($this->app)->grant($person, Membership::of(self::TENANT, CarbonImmutable::now()))->grant($person, Membership::of('tenant-2'));

        $verdict = DB::transaction(fn (): LinkEligibilityVerdict => $this->adapter()->judge(self::referenceOf($person), self::connection()));

        self::assertSame(LinkEligibilityVerdict::ELIGIBLE, $verdict);
    }

    /**
     * Rows of `[memberships]`: each set that holds no accepted membership of
     * the connection's tenant.
     *
     * @return iterable<string, array{0: list<\SineMacula\Laravel\Iam\Tenancy\Membership>}>
     */
    public static function provideIneligible(): iterable
    {
        yield 'none' => [[]];

        yield 'an invitation not taken up' => [[Membership::of(self::TENANT)]];

        yield 'another tenant\'s' => [[Membership::of('tenant-2', CarbonImmutable::now())]];

        yield 'the tenant in another case' => [[Membership::of('TENANT-1', CarbonImmutable::now())]];

        yield 'a platform principal' => [[Membership::platform(CarbonImmutable::now())]];
    }

    /**
     * No accepted membership of exactly the connection's tenant is ineligible.
     *
     * @param  list<\SineMacula\Laravel\Iam\Tenancy\Membership>  $memberships
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIneligible')]
    public function testNoAcceptedMembershipOfTheConnectionsTenantIsIneligible(array $memberships): void
    {
        $person = $this->createPerson();
        $fake   = FakeMemberships::fake($this->app);

        foreach ($memberships as $membership) {
            $fake->grant($person, $membership);
        }

        self::assertSame(LinkEligibilityVerdict::INELIGIBLE, $this->adapter()->judge(self::referenceOf($person), self::connection()));
    }

    /**
     * An incomplete set answers the membership it holds.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIncompleteSetAnswersTheMembershipItHolds(): void
    {
        $person = $this->createPerson();

        FakeMemberships::fake($this->app)->grant($person, Membership::of(self::TENANT, CarbonImmutable::now()))->incomplete($person);

        self::assertSame(LinkEligibilityVerdict::ELIGIBLE, $this->adapter()->judge(self::referenceOf($person), self::connection()));
    }

    /**
     * A reference that names nobody throws, and memberships that cannot be read
     * propagate their failure.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnresolvedIdentityOrAnUnreadableSetThrows(): void
    {
        $person  = $this->createPerson();
        $failure = new \RuntimeException('Unreadable.');
        $fake    = FakeMemberships::fake($this->app)->failFor($person, $failure);

        try {
            $this->adapter()->judge(new IdentityReference($person->getMorphClass(), 'nobody'), self::connection());

            self::fail('A reference naming nobody was answered.');
        } catch (UnresolvedReferenceException) {
            self::assertSame([], $fake->asked());
        }

        $this->expectExceptionObject($failure);

        $this->adapter()->judge(self::referenceOf($person), self::connection());
    }

    /**
     * The adapter, as the container builds it.
     *
     * @return \SineMacula\Laravel\Iam\Tenancy\LinkEligibilityAdapter
     */
    private function adapter(): LinkEligibilityAdapter
    {
        $adapter = $this->app?->make(LinkEligibilityAdapter::class);

        self::assertInstanceOf(LinkEligibilityAdapter::class, $adapter);

        return $adapter;
    }

    /**
     * A connection of the tenant, never stored.
     *
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private static function connection(): Connection
    {
        return (new Connection)->forceFill(['id' => 'connection-1', 'tenant_id' => self::TENANT]);
    }

    /**
     * The reference SSO names the person by.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return \SineMacula\Laravel\Sso\Identities\IdentityReference
     */
    private static function referenceOf(Person $person): IdentityReference
    {
        return new IdentityReference($person->getMorphClass(), (string) $person->id);
    }
}
