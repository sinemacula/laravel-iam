<?php

declare(strict_types = 1);

namespace Tests\Integration\Tenancy;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Iam\Authorization\AuthorizationSeams;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Tenancy\Contracts\GrantScope;
use SineMacula\Laravel\Iam\Tenancy\Membership;
use SineMacula\Laravel\Iam\Tenancy\MembershipSet;
use SineMacula\Laravel\Iam\Tenancy\PrincipalScopeAdapter;
use SineMacula\Laravel\Iam\Testing\FakeMemberships;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * Integration tests for SSO's principal scope, composed of the application's
 * memberships and the grant half (IAM-6.8): `within_tenant` only when both
 * halves are, `outside_tenant` when either is, `unknown` otherwise; an
 * incomplete set of memberships is never `outside_tenant` on its own; with the
 * authorization switch off, `UnknownGrantScope` leaves nobody `within_tenant`;
 * the grant half is not asked once the memberships are `outside_tenant`; and an
 * identity that cannot be resolved, or either half failing, throws.
 *
 * The truth table runs at the connection's own level on every engine; the
 * switched-off default also at READ COMMITTED and REPEATABLE READ on MySQL and
 * PostgreSQL, inside a transaction, as SSO asks it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PrincipalScopeAdapter::class)]
final class PrincipalScopeAdapterTest extends TestCase
{
    use MigratesMembers, RunsAtIsolationLevels, SignsInPeople;

    /** @var string The tenant asked about. */
    private const string TENANT = 'tenant-1';

    /**
     * Rows of `[memberships, grants, verdict]`: the identity's memberships, the
     * grant half's answer, and the verdict.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Iam\Tenancy\MembershipSet, 1: \SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict, 2: \SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideTruthTable(): iterable
    {
        $tenant   = MembershipSet::complete(Membership::of(self::TENANT, CarbonImmutable::now()));
        $none     = MembershipSet::complete();
        $other    = MembershipSet::complete(Membership::of(self::TENANT, CarbonImmutable::now()), Membership::of('tenant-2'));
        $platform = MembershipSet::complete(Membership::of(self::TENANT), Membership::platform());
        $partial  = MembershipSet::incomplete(Membership::of(self::TENANT, CarbonImmutable::now()));
        $partOut  = MembershipSet::incomplete(Membership::of('tenant-2'));

        foreach ([ScopeVerdict::WITHIN_TENANT, ScopeVerdict::UNKNOWN, ScopeVerdict::OUTSIDE_TENANT] as $grants) {

            $label = $grants->value;

            yield 'the tenant alone, grants ' . $label => [$tenant, $grants, $grants];

            yield 'no membership, grants ' . $label => [$none, $grants, $grants];

            yield 'another tenant too, grants ' . $label => [$other, $grants, ScopeVerdict::OUTSIDE_TENANT];

            yield 'a platform principal, grants ' . $label => [$platform, $grants, ScopeVerdict::OUTSIDE_TENANT];

            yield 'incomplete, of the tenant, grants ' . $label => [$partial, $grants, $grants === ScopeVerdict::OUTSIDE_TENANT ? $grants : ScopeVerdict::UNKNOWN];

            yield 'incomplete, of another tenant, grants ' . $label => [$partOut, $grants, $grants === ScopeVerdict::OUTSIDE_TENANT ? $grants : ScopeVerdict::UNKNOWN];
        }
    }

    /**
     * The verdict is `within_tenant` only when both halves are,
     * `outside_tenant` when either is, and `unknown` otherwise; an incomplete
     * set never places the identity outside on its own.
     *
     * @param  \SineMacula\Laravel\Iam\Tenancy\MembershipSet  $memberships
     * @param  \SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict  $grants
     * @param  \SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict  $verdict
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideTruthTable')]
    public function testTheVerdictComposesBothHalves(MembershipSet $memberships, ScopeVerdict $grants, ScopeVerdict $verdict): void
    {
        $person = $this->createPerson();

        $this->holds($person, $memberships);
        $this->app?->instance(GrantScope::class, self::grantsAnswering($grants));

        self::assertSame($verdict, $this->adapter()->judge(self::referenceOf($person), self::TENANT));
    }

    /**
     * With the authorization capability off, the grant half is
     * `UnknownGrantScope`: a member of the tenant alone is `unknown`, never
     * `within_tenant`, and one reaching beyond it is `outside_tenant`, inside
     * SSO's transaction.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    #[WithConfig(AuthorizationSeams::SWITCH, false, defer: false)]
    public function testWithTheAuthorizationSwitchOffTheGrantHalfLeavesNobodyWithin(?string $level): void
    {
        self::runAtIsolationLevel($level);

        [$member, $wider] = [$this->createPerson(), $this->createPerson()];

        FakeMemberships::fake($this->app)
            ->grant($member, Membership::of(self::TENANT, CarbonImmutable::now()))
            ->grant($wider, Membership::of(self::TENANT, CarbonImmutable::now()))
            ->grant($wider, Membership::platform());

        [$inside, $outside] = DB::transaction(fn (): array => [
            $this->adapter()->judge(self::referenceOf($member), self::TENANT),
            $this->adapter()->judge(self::referenceOf($wider), self::TENANT),
        ]);

        self::assertSame(ScopeVerdict::UNKNOWN, $inside);
        self::assertSame(ScopeVerdict::OUTSIDE_TENANT, $outside);
    }

    /**
     * Once the memberships place the identity outside the tenant, the grant
     * half is not asked; otherwise it is asked for the identity and the tenant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheGrantHalfIsAskedOnlyWhenTheMembershipsLeaveItOpen(): void
    {
        [$member, $wider] = [$this->createPerson(), $this->createPerson()];

        FakeMemberships::fake($this->app)->grant($member, Membership::of(self::TENANT))->grant($wider, Membership::of('tenant-2'));

        $grants = \Mockery::mock(GrantScope::class);

        $asked = static fn (Identity $identity, string $tenantId): bool => $identity instanceof Person && $identity->is($member) && $tenantId === self::TENANT;

        $grants->expects('judge')->once()->withArgs($asked)->andReturn(ScopeVerdict::WITHIN_TENANT);

        $this->app?->instance(GrantScope::class, $grants);

        self::assertSame(ScopeVerdict::OUTSIDE_TENANT, $this->adapter()->judge(self::referenceOf($wider), self::TENANT));
        self::assertSame(ScopeVerdict::WITHIN_TENANT, $this->adapter()->judge(self::referenceOf($member), self::TENANT));
    }

    /**
     * A reference that names nobody throws, and either half failing propagates
     * its failure.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnresolvedIdentityOrAFailingHalfThrows(): void
    {
        $person = $this->createPerson();
        $fake   = FakeMemberships::fake($this->app)->grant($person, Membership::of(self::TENANT));

        try {
            $this->adapter()->judge(new IdentityReference($person->getMorphClass(), '0'), self::TENANT);

            self::fail('A reference naming nobody was answered.');
        } catch (UnresolvedReferenceException) {
            self::assertSame([], $fake->asked());
        }

        $failure = new \RuntimeException('Grants unreadable.');
        $grants  = \Mockery::mock(GrantScope::class);

        $grants->allows('judge')->andThrow($failure);

        $this->app?->instance(GrantScope::class, $grants);

        try {
            $this->adapter()->judge(self::referenceOf($person), self::TENANT);

            self::fail('A failing grant half was answered.');
        } catch (\RuntimeException $exception) {
            self::assertSame($failure, $exception);
        }

        $fake->failFor($person, $unreadable = new \RuntimeException('Memberships unreadable.'));

        $this->expectExceptionObject($unreadable);

        $this->adapter()->judge(self::referenceOf($person), self::TENANT);
    }

    /**
     * Have the person hold the memberships given, as complete or not.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  \SineMacula\Laravel\Iam\Tenancy\MembershipSet  $memberships
     * @return void
     */
    private function holds(Person $person, MembershipSet $memberships): void
    {
        $fake = FakeMemberships::fake($this->app);

        foreach ($memberships->memberships as $membership) {
            $fake->grant($person, $membership);
        }

        if ($memberships->isComplete()) {
            return;
        }

        $fake->incomplete($person);
    }

    /**
     * A grant half answering the verdict given.
     *
     * @param  \SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict  $verdict
     * @return \SineMacula\Laravel\Iam\Tenancy\Contracts\GrantScope
     */
    private static function grantsAnswering(ScopeVerdict $verdict): GrantScope
    {
        return new readonly class ($verdict) implements GrantScope {
            /**
             * Constructor.
             *
             * @param  \SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict  $verdict
             */
            public function __construct(

                /** What every judgement answers. */
                private ScopeVerdict $verdict,
            ) {}

            /**
             * The verdict given.
             *
             * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
             * @param  string  $tenantId
             * @return \SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict
             */
            #[\Override]
            public function judge(Identity $identity, string $tenantId): ScopeVerdict
            {
                return $this->verdict;
            }
        };
    }

    /**
     * The adapter, as the container builds it.
     *
     * @return \SineMacula\Laravel\Iam\Tenancy\PrincipalScopeAdapter
     */
    private function adapter(): PrincipalScopeAdapter
    {
        $adapter = $this->app?->make(PrincipalScopeAdapter::class);

        self::assertInstanceOf(PrincipalScopeAdapter::class, $adapter);

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
