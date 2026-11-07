<?php

declare(strict_types = 1);

namespace Tests\Integration\Tenancy;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\TenancyMisconfiguredException;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Tenancy\IdentityMemberships;
use SineMacula\Laravel\Iam\Tenancy\Membership;
use SineMacula\Laravel\Iam\Tenancy\TenantMembershipAdapter;
use SineMacula\Laravel\Iam\Testing\FakeMemberships;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\MembershipStanding;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Tenancy\RecordsMembershipReadModes;
use Tests\TestCase;

/**
 * Integration tests for SSO's tenant membership, answered from the
 * application's memberships (IAM-7.4): a membership of exactly the tenant
 * asked, accepted by the person, is the standing, at the time the person
 * accepted it; one not accepted, another tenant's, a platform principal or none
 * is no standing; an incomplete set answers the memberships it holds; the
 * memberships are asked on the write connection inside SSO's transaction; and
 * an identity that cannot be resolved, memberships that cannot be read, or none
 * configured, throw.
 *
 * The scenarios run at the connection's own level on every engine, then at READ
 * COMMITTED and REPEATABLE READ on MySQL and PostgreSQL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TenantMembershipAdapter::class)]
#[CoversClass(IdentityMemberships::class)]
final class TenantMembershipAdapterTest extends TestCase
{
    use MigratesMembers, RunsAtIsolationLevels, SignsInPeople;

    /** @var string The tenant asked about. */
    private const string TENANT = 'tenant-1';

    /**
     * A membership of the tenant the person accepted is the standing, at the
     * time they accepted it, inside SSO's transaction.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAnAcceptedMembershipIsTheStanding(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person   = $this->createPerson();
        $accepted = CarbonImmutable::parse('2026-03-01 12:00:00');

        FakeMemberships::fake($this->app)->grant($person, Membership::of(self::TENANT, $accepted))->grant($person, Membership::of('tenant-2', $accepted->addDay()));

        $standing = DB::transaction(fn (): MembershipStanding => $this->adapter()->standing(self::referenceOf($person), self::TENANT));

        self::assertSame($accepted, $standing->acceptedAt);
        self::assertTrue($standing->wasAcceptedBefore($accepted->addSecond()));
        self::assertFalse($standing->wasAcceptedBefore($accepted));
    }

    /**
     * Rows of `[memberships]`: each set that holds no membership of the tenant
     * the person accepted.
     *
     * @return iterable<string, array{0: list<\SineMacula\Laravel\Iam\Tenancy\Membership>}>
     */
    public static function provideNoStanding(): iterable
    {
        yield 'none' => [[]];

        yield 'not accepted' => [[Membership::of(self::TENANT)]];

        yield 'another tenant\'s' => [[Membership::of('tenant-2', CarbonImmutable::now())]];

        yield 'the tenant in another case' => [[Membership::of('Tenant-1', CarbonImmutable::now())]];

        yield 'a platform principal' => [[Membership::platform(CarbonImmutable::now())]];
    }

    /**
     * No accepted membership of exactly the tenant is no standing.
     *
     * @param  list<\SineMacula\Laravel\Iam\Tenancy\Membership>  $memberships
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideNoStanding')]
    public function testNoAcceptedMembershipOfTheTenantIsNoStanding(array $memberships): void
    {
        $person = $this->createPerson();
        $fake   = FakeMemberships::fake($this->app);

        foreach ($memberships as $membership) {
            $fake->grant($person, $membership);
        }

        self::assertNull($this->adapter()->standing(self::referenceOf($person), self::TENANT)->acceptedAt);
    }

    /**
     * An incomplete set answers the membership it holds: holding it is known,
     * whatever else the set misses.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIncompleteSetAnswersTheMembershipItHolds(): void
    {
        $person   = $this->createPerson();
        $accepted = CarbonImmutable::parse('2026-03-01 12:00:00');

        FakeMemberships::fake($this->app)->grant($person, Membership::of(self::TENANT, $accepted))->incomplete($person);

        self::assertSame($accepted, $this->adapter()->standing(self::referenceOf($person), self::TENANT)->acceptedAt);
    }

    /**
     * The memberships are asked pinned to the write connection, for the
     * identity the reference names, and the connection reads from its replica
     * again afterwards.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheMembershipsAreAskedOnTheWriteConnection(): void
    {
        $person   = $this->createPerson();
        $fake     = new FakeMemberships;
        $recorder = new RecordsMembershipReadModes($fake->grant($person, Membership::of(self::TENANT, CarbonImmutable::now())));

        $this->app?->instance(FakeMemberships::MEMBERSHIPS, $recorder);

        $this->adapter()->standing(self::referenceOf($person), self::TENANT);

        self::assertSame([true], $recorder->pinned);
        self::assertSame([['identity' => Person::class, 'id' => (string) $person->id]], $fake->asked());
        self::assertFalse((new \ReflectionProperty($person->getConnection(), 'readOnWriteConnection'))->getValue($person->getConnection()));
    }

    /**
     * A reference that names nobody throws, and the memberships are not asked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnresolvedIdentityThrows(): void
    {
        $fake = FakeMemberships::fake($this->app);

        try {
            $this->adapter()->standing(new IdentityReference((new Person)->getMorphClass(), '999999'), self::TENANT);

            self::fail('A reference naming nobody was answered.');
        } catch (UnresolvedReferenceException $exception) {
            self::assertSame(ReferenceKind::IDENTITY, $exception->kind);
        }

        self::assertSame([], $fake->asked());
    }

    /**
     * Memberships that cannot be read throw out of the adapter.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testMembershipsThatCannotBeReadThrow(): void
    {
        $person  = $this->createPerson();
        $failure = new \RuntimeException('Unreadable.');

        FakeMemberships::fake($this->app)->failFor($person, $failure);

        $this->expectExceptionObject($failure);

        $this->adapter()->standing(self::referenceOf($person), self::TENANT);
    }

    /**
     * Asked with no memberships configured, the adapter throws rather than
     * answer no membership.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNoMembershipsConfiguredThrows(): void
    {
        $person = $this->createPerson();

        $this->expectException(TenancyMisconfiguredException::class);
        $this->expectExceptionMessage('iam.tenancy.memberships');

        $this->adapter()->standing(self::referenceOf($person), self::TENANT);
    }

    /**
     * The adapter, as the container builds it.
     *
     * @return \SineMacula\Laravel\Iam\Tenancy\TenantMembershipAdapter
     */
    private function adapter(): TenantMembershipAdapter
    {
        $adapter = $this->app?->make(TenantMembershipAdapter::class);

        self::assertInstanceOf(TenantMembershipAdapter::class, $adapter);

        return $adapter;
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
