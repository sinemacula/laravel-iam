<?php

declare(strict_types = 1);

namespace Tests\Integration\Authorization;

use Illuminate\Auth\SessionGuard;
use Illuminate\Contracts\Auth\Authenticatable;
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
use Tests\Fixtures\Authorization\UnmarkedServiceAccount;
use Tests\Fixtures\Models\Machine;
use Tests\TestCase;

/**
 * Integration tests for the subject resolver answered from the caller.
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
     * The request's caller is the subject.
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
     * A caller without a session is the subject with none.
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
     * The guard's own principal is the caller, with its session.
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
     * Any other principal has no session.
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
     * A reloaded copy of the caller is the caller.
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
     * Each job in a worker is decided about its own caller.
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

        $reset->reset();

        self::assertSame([], array_keys(self::callerMemos()));

        $session = $this->signInAndActOnSession($second);

        self::assertSubject(new Subject($second, $second, null, self::GUARD, self::GUARD, self::keyOf($session)), $this->resolver()->resolve());

        $reset->reset();

        self::assertNull($this->resolver()->resolve());
    }

    /**
     * A non-principal identity and any other model are their own subject.
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
     * Another kind of guard is answered as authorization's own resolver.
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
     * A session on another kind of guard carries no cap.
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
     * Rows of `[machine signed in, its model]`.
     *
     * @return iterable<string, array{0: class-string<\Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model>}>
     */
    public static function provideMachines(): iterable
    {
        yield 'a machine identity' => [Machine::class];

        yield 'a principal acting for a machine identity' => [UnmarkedServiceAccount::class];
    }

    /**
     * A machine's session on another kind of guard is allowed nothing.
     *
     * @param  class-string<\Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model>  $kind
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideMachines')]
    public function testAMachinesSessionOfAnotherKindOfGuardIsAllowedNothing(string $kind): void
    {
        $machine = $kind::query()->create(['name' => 'Reporting']);
        $store   = $this->resolved('session.store');

        self::assertInstanceOf(Store::class, $store);
        self::assertInstanceOf(Authenticatable::class, $machine);

        $this->app?->make('config')->set('auth.guards.web', ['driver' => 'session', 'provider' => 'machines']);
        $this->app?->make('config')->set('auth.providers.machines', ['driver' => 'model', 'model' => $kind]);

        $store->start();
        request()->setLaravelSession($store);

        Auth::shouldUse('web');
        Auth::guard()->login($machine);

        $subject = $this->resolver()->resolve();
        $source  = $this->resolved(SessionPolicySource::class);

        self::assertInstanceOf(SessionPolicySource::class, $source);
        self::assertSame($store->getId(), $subject?->session);
        self::assertSame([], $subject->scopes?->scopes());
        self::assertSame([], $source->scopesFor($subject));
    }

    /**
     * A principal keeps its identity and tenant whatever the default guard.
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
     * Assert the subject matches the one expected.
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
     * Assert the subject is the seat acting for its holder, with no session.
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
     * Resolve the abstract from the application under test.
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
