<?php

declare(strict_types = 1);

namespace Tests\Integration\Mfa;

use Illuminate\Auth\Events\Login;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\ApplicationResolverAdapter;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Contracts\ApplicationResolver;
use SineMacula\Laravel\Mfa\Contracts\GuardApplicationResolver;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\ApplicationResolverTests;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\GuardApplicationResolverTests;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * Integration tests for MFA's application named after the guard (IAM-3.12): the
 * guard MFA reads the caller through or names a sign-in after, and otherwise
 * the default guard as `Auth::shouldUse()` leaves it, whether the request is
 * signed in or a guest's, the same guard MFA would name without a resolver, and
 * the application of the caller MFA then reads from a request; a guard that
 * names nothing throws (IAM-8.2), rolling back the transaction it is asked in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ApplicationResolverAdapter::class)]
final class ApplicationResolverAdapterTest extends TestCase
{
    use ApplicationResolverTests, GuardApplicationResolverTests, MigratesMembers, SignsInPeople;

    /** @var string A second guard of `laravel-authentication`'s, an administrator's panel, say. */
    private const string ADMIN = 'admin';

    /** @var string A guard that holds no sessions of `laravel-authentication`'s: a panel's session guard. */
    private const string PANEL = 'panel';

    /**
     * The application is the guard that serves the request: the default guard,
     * until a route's `auth` middleware has another serve it.
     *
     * @return void
     */
    public function testTheApplicationIsTheGuardThatServesTheRequest(): void
    {
        self::assertSame(self::GUARD, $this->adapter()->resolve($this->request()));

        Auth::shouldUse(self::ADMIN);

        self::assertSame(self::ADMIN, $this->adapter()->resolve($this->request()));
    }

    /**
     * A signed-in request and a guest's are named alike, as MFA names a request
     * without a resolver, so a change made outside a signed-in request stays on
     * the guard MFA would have named.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignedInRequestAndAGuestsAreNamedAlike(): void
    {
        $guest = $this->adapter()->resolve($this->request());

        $this->signInAndActOnSession($this->createPerson());

        self::assertSame(self::GUARD, $guest);
        self::assertSame($guest, $this->adapter()->resolve($this->request()));
    }

    /**
     * Nothing the request carries names the application: a path, a host, a
     * header, a query and a body each naming another guard leave it the guard
     * that serves the request, or the guard MFA names.
     *
     * @return void
     */
    public function testNothingTheRequestCarriesNamesTheApplication(): void
    {
        $body    = ['guard' => self::ADMIN, 'application' => self::ADMIN];
        $request = Request::create('https://admin.example.test/admin/mfa?guard=' . self::ADMIN, 'POST', $body, server: ['HTTP_X_GUARD' => self::ADMIN]);

        self::assertSame(self::GUARD, $this->adapter()->resolve($request));
        self::assertSame(self::GUARD, $this->adapter()->resolveForGuard($request, self::GUARD));
    }

    /**
     * Bound as MFA's application resolver, the guard it names is the
     * application of the caller MFA reads from a request.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testMfaNamesTheApplicationItNames(): void
    {
        $this->app?->bind(ApplicationResolver::class, ApplicationResolverAdapter::class);

        Auth::shouldUse(self::ADMIN);

        self::assertSame(self::ADMIN, CallerContext::fromRequest($this->request())->application);
    }

    /**
     * A caller MFA reads through another guard than the default is named after
     * that guard while the adapter is bound, as MFA alone names it, while the
     * default guard stays the one that serves the request.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACallerReadThroughAnotherGuardIsNamedAfterThatGuard(): void
    {
        $this->app?->offsetUnset(ApplicationResolver::class);

        self::assertSame(self::ADMIN, CallerContext::fromRequest($this->request(), self::ADMIN)->application);

        $this->app?->bind(ApplicationResolver::class, ApplicationResolverAdapter::class);

        self::assertSame(self::ADMIN, CallerContext::fromRequest($this->request(), self::ADMIN)->application);
        self::assertSame(self::GUARD, CallerContext::fromRequest($this->request())->application);
        self::assertSame(self::GUARD, Auth::getDefaultDriver());
    }

    /**
     * A sign-in on a guard other than the default, one that holds no sessions
     * of `laravel-authentication`'s included, begins MFA's sign-in on the
     * application named after that guard, without throwing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInOnAnotherGuardIsNamedAfterThatGuard(): void
    {
        $person = $this->createPerson();
        $store  = \Mockery::mock(ProofStore::class);

        $store->shouldReceive('begin')->once()->with($person, self::PANEL, \Mockery::type('string'));

        $this->app?->instance(ProofStore::class, $store);

        self::assertInstanceOf(ApplicationResolverAdapter::class, $this->app?->make(ApplicationResolver::class));

        Event::dispatch(new Login(self::PANEL, $person, false));

        self::assertSame(self::GUARD, Auth::getDefaultDriver());
    }

    /**
     * Rows of `[default guard]` that name nothing: an empty name and a blank
     * one.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideDefaultGuardsThatNameNothing(): iterable
    {
        yield 'empty' => [''];

        yield 'blank' => ['  '];
    }

    /**
     * A default guard that names nothing names no application, and is refused
     * as no guard, never answered blank.
     *
     * @param  string  $guard
     * @return void
     */
    #[DataProvider('provideDefaultGuardsThatNameNothing')]
    public function testADefaultGuardThatNamesNothingIsUnresolved(string $guard): void
    {
        Config::set('auth.defaults.guard', $guard);

        $exception = self::assertUnresolved(fn (): string => $this->adapter()->resolve($this->request()));

        self::assertSame($guard, $exception->application);
    }

    /**
     * A guard MFA names that names nothing names no application, and is refused
     * as no guard, never answered blank, whatever the default guard.
     *
     * @return void
     */
    public function testAGuardThatNamesNothingIsUnresolved(): void
    {
        foreach (['', '  '] as $guard) {

            $exception = self::assertUnresolved(fn (): string => $this->adapter()->resolveForGuard($this->request(), $guard));

            self::assertSame($guard, $exception->application);
        }
    }

    /**
     * A refusal inside the transaction MFA asks it in rolls back what the
     * transaction wrote before it.
     *
     * @return void
     */
    public function testARefusalRollsBackTheTransactionItIsAskedIn(): void
    {
        Config::set('auth.defaults.guard', '');

        self::assertUnresolved(fn (): string => DB::transaction(function (): string {

            $this->createPerson();

            return $this->adapter()->resolve($this->request());
        }));

        self::assertSame(0, Person::query()->count());
    }

    /**
     * The resolver under test.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\ApplicationResolver
     */
    #[\Override]
    protected function applicationResolver(): ApplicationResolver
    {
        return $this->adapter();
    }

    /**
     * A request for an application: the one being served.
     *
     * @return \Illuminate\Http\Request
     */
    #[\Override]
    protected function applicationRequest(): Request
    {
        return $this->request();
    }

    /**
     * The guard-aware resolver under test.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\GuardApplicationResolver
     */
    #[\Override]
    protected function guardApplicationResolver(): GuardApplicationResolver
    {
        return $this->adapter();
    }

    /**
     * A request for an application: the one being served.
     *
     * @return \Illuminate\Http\Request
     */
    #[\Override]
    protected function guardApplicationRequest(): Request
    {
        return $this->request();
    }

    /**
     * A guard the request may be served through other than the default: the
     * administrators'.
     *
     * @return string
     */
    #[\Override]
    protected function applicationGuard(): string
    {
        return self::ADMIN;
    }

    /**
     * Declare the administrators' guard and a panel's session guard beside the
     * guard people sign in on.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        Config::set('auth.guards.' . self::ADMIN, ['driver' => 'jwt', 'provider' => 'people']);
        Config::set('auth.guards.' . self::PANEL, ['driver' => 'session', 'provider' => 'people']);
    }

    /**
     * Fail the test unless the call is refused as naming no guard, and return
     * the refusal.
     *
     * @param  \Closure(): mixed  $call
     * @return \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private static function assertUnresolved(\Closure $call): UnresolvedReferenceException
    {
        try {
            $call();
        } catch (UnresolvedReferenceException $exception) {
            self::assertSame(ReferenceKind::GUARD, $exception->kind);

            return $exception;
        }

        self::fail('A guard that names nothing named an application.');
    }

    /**
     * The request being served.
     *
     * @return \Illuminate\Http\Request
     */
    private function request(): Request
    {
        $request = $this->app?->make('request');

        self::assertInstanceOf(Request::class, $request);

        return $request;
    }

    /**
     * Resolve the adapter under test from the container.
     *
     * @return \SineMacula\Laravel\Iam\Mfa\ApplicationResolverAdapter
     */
    private function adapter(): ApplicationResolverAdapter
    {
        $adapter = $this->app?->make(ApplicationResolverAdapter::class);

        self::assertInstanceOf(ApplicationResolverAdapter::class, $adapter);

        return $adapter;
    }
}
