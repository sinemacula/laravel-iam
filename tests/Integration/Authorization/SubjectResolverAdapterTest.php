<?php

declare(strict_types = 1);

namespace Tests\Integration\Authorization;

use Illuminate\Auth\SessionGuard;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Auth;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Contracts\SessionPolicySource;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Iam\Authorization\SubjectResolverAdapter;
use SineMacula\Laravel\Iam\Workers\WorkerReset;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Authorization\Organisation;
use Tests\Fixtures\Authorization\Seat;
use Tests\Fixtures\Authorization\Staff;
use Tests\Fixtures\Models\Machine;
use Tests\TestCase;

/**
 * Integration tests for `laravel-authorization`'s subject resolver, answered
 * from `laravel-authentication`'s caller (IAM-6.1): the request's caller is the
 * subject, its principal with its identity, active tenant, application and
 * session; a request with no caller has none. The model Laravel's Gate hands
 * over is the caller, with its session, only when it is the default guard's
 * principal or the identity acting as it, and the request's caller is never
 * read for it; any other principal is a subject in its own tenant with no
 * session, and any other model, an identity that is not the caller's and no
 * principal among them, is its own subject. A default guard that is not
 * `laravel-authentication`'s is answered as `laravel-authorization`'s own
 * resolver answers it, but for a principal, which still acts for its identity
 * in its own tenant.
 *
 * Each scenario that signs in runs at the connection's own level on every
 * engine, then at READ COMMITTED and REPEATABLE READ on MySQL and PostgreSQL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SubjectResolverAdapter::class)]
#[CoversClass(WorkerReset::class)]
final class SubjectResolverAdapterTest extends TestCase
{
    use MigratesMembers, RunsAtIsolationLevels, SignsInPeople;

    /** @var string The prefix of the request attributes `laravel-authentication` keeps the request's callers under. */
    private const string CALLER_MEMO = 'authentication.caller';

    /**
     * The request's caller is the subject: its principal, its identity, no
     * tenant for a person acting in none, its guard as the application, and its
     * session's key.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testTheRequestsCallerIsTheSubject(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        self::assertSubject(new Subject($person, $person, null, self::GUARD, self::GUARD, self::keyOf($session)), $this->resolver()->resolve());
    }

    /**
     * A caller the guard holds without a session (one bound in trust, as an
     * application's own sign-in binds it) is the subject with no session, so no
     * authentication requirement is met for it.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testACallerWithoutASessionIsTheSubjectWithNone(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person = $this->createPerson();

        Auth::guard(self::GUARD)->setUser($person);

        self::assertSubject(new Subject($person, $person, null, self::GUARD, self::GUARD), $this->resolver()->resolve());
        self::assertSubject(new Subject($person, $person, null, self::GUARD, self::GUARD), $this->resolver()->forUser($person));
    }

    /**
     * A request with no caller has no subject.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequestWithNoCallerHasNoSubject(): void
    {
        self::assertNull($this->resolver()->resolve());
    }

    /**
     * The model the Gate hands over is the caller, with its tenant and session,
     * when it is the default guard's principal, and the request's caller is
     * never read for it.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testTheGuardsOwnPrincipalIsTheCallerWithItsSession(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);
        $user    = Auth::guard(self::GUARD)->user();

        self::assertSame($person->getKey(), $user?->getAuthIdentifier());
        self::assertIsObject($user);
        self::assertSubject(new Subject($user, $user, null, self::GUARD, self::GUARD, self::keyOf($session)), $this->resolver()->forUser($user));
        self::assertSame([], array_keys(self::callerMemos()));
    }

    /**
     * Any other principal is a subject in its own tenant with no session: one
     * the caller names, and the caller's own model while the guard has not
     * resolved who it serves.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAnyOtherPrincipalHasNoSession(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person  = $this->createPerson();
        $someone = $this->createPerson();

        self::assertSubject(new Subject($person, $person, null, self::GUARD, self::GUARD), $this->resolver()->forUser($person));

        $this->signInAndActOnSession($person);

        self::assertSubject(new Subject($someone, $someone, null, self::GUARD, self::GUARD), $this->resolver()->forUser($someone));
    }

    /**
     * The caller's own model loaded again, apart from the one the guard holds
     * (`Auth::user()->fresh()`, a find by the caller's key, the model handed
     * over before the guard resolved), is still the caller, with its session.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testACopyOfTheCallerLoadedAgainIsTheCaller(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);
        $user    = Auth::guard(self::GUARD)->user();

        self::assertInstanceOf(Model::class, $user);

        foreach ([$person, $person->fresh(), $person::query()->findOrFail($person->getKey())] as $copy) {

            self::assertNotSame($user, $copy);
            self::assertIsObject($copy);
            self::assertSubject(new Subject($user, $user, null, self::GUARD, self::GUARD, self::keyOf($session)), $this->resolver()->forUser($copy));
        }
    }

    /**
     * In a long-lived worker, whose jobs share one request, each job is decided
     * about its own caller: once the worker resets between jobs, as it does
     * before each one, the first job's caller is no subject of the next, which
     * is decided about the one it signs in, and a job that signs nobody in has
     * no subject.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testEachJobInAWorkerIsDecidedAboutItsOwnCaller(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $first  = $this->createPerson();
        $second = $this->createPerson();

        $this->signInAndActOnSession($first);

        self::assertTrue(self::isSame($first, $this->resolver()->resolve()?->subject));

        $reset = new WorkerReset($this->app ?? self::fail('The application has not booted.'));

        $reset->forgetMemberState();

        self::assertSame([], array_keys(self::callerMemos()));

        $session = $this->signInAndActOnSession($second);

        self::assertSubject(new Subject($second, $second, null, self::GUARD, self::GUARD, self::keyOf($session)), $this->resolver()->resolve());

        $reset->forgetMemberState();

        self::assertNull($this->resolver()->resolve());
    }

    /**
     * An identity that is not the caller's and no principal is its own subject
     * and identity, with no tenant and no session, as `laravel-authorization`'s
     * own resolver answers it, and so is any other model.
     *
     * @return void
     */
    public function testAnIdentityThatIsNoPrincipalAndAnyOtherModelAreTheirOwnSubject(): void
    {
        $model   = new \stdClass;
        $machine = (new Machine)->forceFill(['id' => 7]);

        self::assertSubject(new Subject($model, $model, null, self::GUARD, self::GUARD), $this->resolver()->forUser($model));
        self::assertSubject(new Subject($machine, $machine, null, self::GUARD, self::GUARD), $this->resolver()->forUser($machine));
    }

    /**
     * A default guard that is not `laravel-authentication`'s is answered as
     * `laravel-authorization`'s own resolver answers it: its user, as its own
     * subject on the guard, and no subject without one.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAnotherKindOfGuardIsAnsweredAsLaravelAuthorizationsOwn(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person = $this->createPerson();

        $this->app?->make('config')->set('auth.guards.web', ['driver' => 'session', 'provider' => 'people']);

        Auth::shouldUse('web');

        self::assertInstanceOf(SessionGuard::class, Auth::guard());
        self::assertNull($this->resolver()->resolve());

        Auth::guard()->setUser($person);

        self::assertSubject(new Subject($person, $person, null, 'web', 'web'), $this->resolver()->resolve());
        self::assertSubject(new Subject($person, $person, null, 'web', 'web'), $this->resolver()->forUser($person));
    }

    /**
     * On a default guard that is not `laravel-authentication`'s, a user signed
     * in with the request's session carries no cap, since such a session
     * carries no scopes, so the session policy source looks nothing up for it
     * and caps nothing; a user with no session, and any other model, says
     * nothing of its scopes and is its own subject as that resolver answers it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionOfAnotherKindOfGuardCarriesNoCap(): void
    {
        $person = $this->createPerson();
        $staff  = Staff::query()->create(['name' => 'Ada Lovelace', 'email' => 'ada@example.test']);
        $store  = $this->resolved('session.store');

        self::assertInstanceOf(Store::class, $store);

        $this->app?->make('config')->set('auth.guards.web', ['driver' => 'session', 'provider' => 'people']);

        $store->start();
        request()->setLaravelSession($store);

        Auth::shouldUse('web');
        Auth::guard()->login($person);

        $subject = $this->resolver()->resolve();
        $source  = $this->resolved(SessionPolicySource::class);

        self::assertInstanceOf(SessionPolicySource::class, $source);
        self::assertSame($store->getId(), $subject?->session);
        self::assertFalse($subject->scopes?->isCapped() ?? true);
        self::assertNull($source->scopesFor($subject));

        $other = $this->resolver()->forUser($staff);

        self::assertSubject(new Subject($staff, $staff, null, 'web', 'web'), $other);
        self::assertNull($other->scopes);
    }

    /**
     * A principal handed in is decided about with the identity it acts for and
     * in its own tenant whichever guard is the default: one that is not
     * `laravel-authentication`'s answers it as `laravel-authentication`'s does,
     * only on that guard, never as its own identity in no tenant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPrincipalKeepsItsIdentityAndTenantWhicheverGuardIsTheDefault(): void
    {
        $staff = Staff::query()->create(['name' => 'Ada Lovelace', 'email' => 'ada@example.test']);
        $seat  = Seat::query()->create(['person_id' => $staff->id, 'tenant_id' => 'acme']);

        self::assertPrincipalSubject($seat, $staff, self::GUARD, $this->resolver()->forUser($seat));

        $this->app?->make('config')->set('auth.guards.web', ['driver' => 'session', 'provider' => 'people']);

        Auth::shouldUse('web');

        self::assertInstanceOf(SessionGuard::class, Auth::guard());
        self::assertPrincipalSubject($seat, $staff, 'web', $this->resolver()->forUser($seat));
    }

    /**
     * The bound subject resolver.
     *
     * @return \SineMacula\Laravel\Iam\Authorization\SubjectResolverAdapter
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function resolver(): SubjectResolverAdapter
    {
        $resolver = $this->resolved(SubjectResolver::class);

        self::assertInstanceOf(SubjectResolverAdapter::class, $resolver);

        return $resolver;
    }

    /**
     * The callers `laravel-authentication` keeps on the request, by key.
     *
     * @return array<string, mixed>
     */
    private static function callerMemos(): array
    {
        return array_filter(request()->attributes->all(), static fn (string $key): bool => str_starts_with($key, self::CALLER_MEMO), ARRAY_FILTER_USE_KEY);
    }

    /**
     * The session's key, as `laravel-authorization`'s subject names it.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $session
     * @return string
     */
    private static function keyOf(Model $session): string
    {
        $key = $session->getKey();

        self::assertTrue(is_string($key) || is_int($key));

        return (string) $key;
    }

    /**
     * Assert the subject is the one expected: the same models, compared as
     * models where they are, the same tenant, application, guard and session.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $expected
     * @param  ?\SineMacula\Laravel\Authorization\Subject  $actual
     * @return void
     */
    private static function assertSubject(Subject $expected, ?Subject $actual): void
    {
        self::assertNotNull($actual);
        self::assertTrue(self::isSame($expected->subject, $actual->subject), 'The subject differs.');
        self::assertTrue(self::isSame($expected->identity, $actual->identity), 'The identity differs.');
        self::assertSame($expected->tenant, $actual->tenant);
        self::assertSame($expected->application, $actual->application);
        self::assertSame($expected->guard, $actual->guard);
        self::assertSame($expected->session, $actual->session);
    }

    /**
     * Assert the subject is the seat, acting for the person who holds it, in
     * the organisation it names, on the guard given, with no session.
     *
     * @param  \Tests\Fixtures\Authorization\Seat  $seat
     * @param  \Tests\Fixtures\Authorization\Staff  $staff
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authorization\Subject  $actual
     * @return void
     */
    private static function assertPrincipalSubject(Seat $seat, Staff $staff, string $guard, Subject $actual): void
    {
        self::assertTrue(self::isSame($seat, $actual->subject), 'The subject differs.');
        self::assertTrue(self::isSame($staff, $actual->identity), 'The identity differs.');
        self::assertEquals(new Organisation('acme'), $actual->tenant);
        self::assertSame($guard, $actual->application);
        self::assertSame($guard, $actual->guard);
        self::assertNull($actual->session);
    }

    /**
     * Whether the two are the same: the same model, or the same object.
     *
     * @param  ?object  $expected
     * @param  ?object  $actual
     * @return bool
     */
    private static function isSame(?object $expected, ?object $actual): bool
    {
        return $expected instanceof Model && $actual instanceof Model ? $expected->is($actual) : $expected === $actual;
    }

    /**
     * Resolve the abstract from the application under test, as anything that
     * asks for it does.
     *
     * @param  string  $abstract
     * @return mixed
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function resolved(string $abstract): mixed
    {
        return $this->app?->make($abstract);
    }
}
