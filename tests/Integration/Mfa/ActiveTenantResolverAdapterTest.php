<?php

declare(strict_types = 1);

namespace Tests\Integration\Mfa;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\ActiveTenantResolverAdapter;
use SineMacula\Laravel\Mfa\Contracts\ActiveTenantResolver;
use SineMacula\Laravel\Mfa\Contracts\TenantRequirement;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Resolvers\ClaimedTenant;
use Tests\Fixtures\Resolvers\RecordsActiveTenants;
use Tests\Fixtures\Resolvers\RecordsTenants;
use Tests\TestCase;

/**
 * Tests for MFA's active tenant, read from the validated session.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ActiveTenantResolverAdapter::class)]
final class ActiveTenantResolverAdapterTest extends TestCase
{
    use MigratesMembers, RunsAtIsolationLevels, SignsInPeople;

    /** @var string The tenant the tests' sessions act in. */
    private const string TENANT = 'tenant-01J9Z3';

    /** @var string A tenant the request or a bind claims, which no session records. */
    private const string CLAIMED = 'tenant-claimed';

    /**
     * The tenant is the one the session records, if any.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheTenantIsTheOneTheSessionRecords(): void
    {
        $person = $this->createPerson();

        $this->signInAndActOnSession($person);

        self::assertNull($this->adapter()->activeTenant($person, self::GUARD));

        $this->actInTenant($person, self::TENANT);

        self::assertSame(self::TENANT, $this->adapter()->activeTenant($person, self::GUARD));
    }

    /**
     * A credential validated without a session has no tenant to answer.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACredentialWithoutASessionHasNone(): void
    {
        $person = $this->createPerson();

        $this->actingAsIdentity($person, guard: self::GUARD);

        self::assertNull($this->adapter()->activeTenant($person, self::GUARD));
    }

    /**
     * Only the session's own tenant is the active tenant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNoTenantClaimedBesideTheSessionIsEverTheActiveOne(): void
    {
        $person = $this->createPerson();

        $this->actInTenant($person, self::TENANT);
        $this->actingInTenant(new ClaimedTenant(self::CLAIMED));

        $request = $this->app?->make('request');

        self::assertInstanceOf(Request::class, $request);

        $request->headers->set('X-Tenant', self::CLAIMED);
        $request->merge(['tenant_id' => self::CLAIMED]);

        self::assertSame(self::TENANT, $this->adapter()->activeTenant($person, self::GUARD));
    }

    /**
     * An identity the request serves no session of has no active tenant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityTheRequestServesNoSessionOfHasNone(): void
    {
        $person = $this->createPerson();

        self::assertNull($this->adapter()->activeTenant($person, self::GUARD));

        $this->actInTenant($this->createPerson(), self::TENANT);

        self::assertNull($this->adapter()->activeTenant($person, self::GUARD));
    }

    /**
     * A sign-in judged before its session exists still signs in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInJudgedBeforeItsSessionIsWrittenSignsIn(): void
    {
        $answers = new RecordsActiveTenants($this->adapter());

        $this->app?->instance(ActiveTenantResolver::class, $answers);

        $result = $this->attemptSignIn($this->createPerson());

        self::assertTrue($result->isSignedIn());
        self::assertNotEmpty($answers->answers);
        self::assertSame([null], array_values(array_unique($answers->answers)));
    }

    /**
     * Once bound, MFA composes its requirement with the session's tenant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testMfaComposesItsRequirementWithTheSessionsTenant(): void
    {
        $tenants = new RecordsTenants;

        $this->app?->bind(ActiveTenantResolver::class, ActiveTenantResolverAdapter::class);
        $this->app?->instance(TenantRequirement::class, $tenants);

        $person = $this->createPerson();

        $this->signInAndActOnSession($person);

        self::assertTrue(Mfa::requirement(self::servedCaller())->isEmpty());
        self::assertSame([], $tenants->tenants);

        $this->actInTenant($person, self::TENANT);

        self::assertSame(Requirement::none()->withAdditionalVerification(RecordsTenants::MAX_AGE)->toArray(), Mfa::requirement(self::servedCaller())->toArray());
        self::assertSame([self::TENANT], $tenants->tenants);
    }

    /**
     * Rows of `[application]` that are no session guard.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideApplicationsThatAreNoSessionGuard(): iterable
    {
        yield 'no guard' => ['not-a-guard'];

        yield 'another kind of guard' => ['web'];

        yield 'none' => [''];
    }

    /**
     * An application that is no session guard throws.
     *
     * @param  string  $application
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideApplicationsThatAreNoSessionGuard')]
    public function testAnApplicationThatIsNoSessionGuardIsUnresolved(string $application): void
    {
        $person = $this->createPerson();

        $this->actInTenant($person, self::TENANT);

        $exception = self::assertUnresolved(fn (): ?string => $this->adapter()->activeTenant($person, $application), ReferenceKind::GUARD);

        self::assertSame($application, $exception->application);
    }

    /**
     * An identity whose key names nothing cannot be resolved, and throws.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityWhoseKeyNamesNothingIsUnresolved(): void
    {
        $this->actInTenant($this->createPerson(), self::TENANT);

        $this->expectException(UnsupportedIdentifierException::class);

        $this->adapter()->activeTenant(new Person, self::GUARD);
    }

    /**
     * A refusal rolls back the transaction it is asked in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefusalRollsBackTheTransactionItIsAskedIn(): void
    {
        $person = $this->createPerson();

        self::assertUnresolved(fn (): ?string => DB::transaction(function () use ($person): ?string {

            $person->update(['name' => 'Augusta Ada King']);

            return $this->adapter()->activeTenant($person, 'web');
        }), ReferenceKind::GUARD);

        self::assertSame('Ada Lovelace', $person->refresh()->name);
    }

    /**
     * Inside a transaction it runs no query.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testInsideATransactionItRunsNoQuery(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        $person  = $this->createPerson();
        $session = $this->actInTenant($person, self::TENANT);

        $session->newQuery()->whereKey($session->getKey())->update(['tenant_id' => self::CLAIMED]);

        $queries = [];
        $tenant  = DB::transaction(function () use ($person, &$queries): ?string {

            Person::query()->whereKey($person->getKey())->lockForUpdate()->firstOrFail();

            DB::listen(static function (QueryExecuted $query) use (&$queries): void {
                $queries[] = $query->sql;
            });

            return $this->adapter()->activeTenant($person, self::GUARD);
        });

        self::assertSame(self::TENANT, $tenant);
        self::assertSame([], $queries);
    }

    /**
     * Sign the person in and act on a session in the tenant.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  string  $tenant
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession
     *
     * @throws \Throwable
     */
    private function actInTenant(Person $person, string $tenant): EloquentSession&Model
    {
        $session = $this->signIn($person)->record;

        $session->forceFill([$session->getTenantIdName() => $tenant])->save();

        $this->actingOnSession($session, self::GUARD);

        return $session;
    }

    /**
     * Assert the call is refused as unresolved, and return the refusal.
     *
     * @param  \Closure(): mixed  $call
     * @param  \SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind  $kind
     * @return \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private static function assertUnresolved(\Closure $call, ReferenceKind $kind): UnresolvedReferenceException
    {
        try {
            $call();
        } catch (UnresolvedReferenceException $exception) {
            self::assertSame($kind, $exception->kind);

            return $exception;
        }

        self::fail('An unresolved reference was answered.');
    }

    /**
     * Resolve the adapter under test from the container.
     *
     * @return \SineMacula\Laravel\Iam\Mfa\ActiveTenantResolverAdapter
     */
    private function adapter(): ActiveTenantResolverAdapter
    {
        $adapter = $this->app?->make(ActiveTenantResolverAdapter::class);

        self::assertInstanceOf(ActiveTenantResolverAdapter::class, $adapter);

        return $adapter;
    }
}
