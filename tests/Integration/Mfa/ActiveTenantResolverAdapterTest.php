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
 * Integration tests for MFA's active tenant read from the tenant
 * `laravel-authentication`'s validated session records (IAM-3.12): the
 * session's own tenant, never one a request claims or a bind sets on the guard
 * beside the session; none for a session in no tenant, for an identity the
 * request serves no session of, and for a sign-in judged before its session is
 * written, which therefore still signs in; the tenant MFA then composes its
 * requirement with; an application that is no session guard, or an identity
 * whose key names nothing, throws (IAM-8.2), rolling back the transaction it is
 * asked in; and inside a transaction, at either isolation level, it runs no
 * query, so it takes no lock and reads no tenant committed after the session
 * was validated.
 *
 * The sessions are real ones, signed in through `laravel-authentication` with a
 * password, their tenant written on their row as a sign-in into a tenant
 * records it, and the adapter is resolved on its own.
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
     * The tenant is the one the identity's validated session records, and a
     * session in no tenant answers none.
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
     * A credential the guard validated without a session, such as an access
     * token that records none, has no session's tenant to answer.
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
     * Neither a tenant the request claims nor one a bind sets on the guard
     * beside the session is ever the active tenant: only the session's own.
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
     * An identity the request serves no session of has no active tenant: a
     * guest's request, and another identity's session in a tenant.
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
     * A sign-in MFA judges before its session is written asks for the active
     * tenant, is answered none, and signs in.
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
     * Bound as MFA's active tenant resolver, the session's tenant is the one
     * MFA composes the identity's requirement with.
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
     * Rows of `[application]` that are no guard of `laravel-authentication`'s
     * holding sessions: a name no guard is declared under, Laravel's own
     * session guard, and none.
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
     * An application that is no session guard cannot be resolved, and throws
     * rather than answering no tenant.
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

        self::assertUnresolved(fn (): ?string => $this->adapter()->activeTenant(new Person, self::GUARD), ReferenceKind::IDENTITY);
    }

    /**
     * A refusal inside the transaction MFA asks it in rolls back what the
     * transaction wrote before it.
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
     * Inside a transaction that already holds the identity's lock, at either
     * isolation level, it runs no query: it takes no lock after the
     * transaction's, and a tenant committed to the session's row after the
     * session was validated is not the one the request acts in.
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
     * Sign the person in, record the tenant on the new session's row as a
     * sign-in into the tenant records it, and act on the session as a bearer
     * request for it would.
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
     * Fail the test unless the call is refused as an unresolved reference of
     * the kind given, and return the refusal.
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
