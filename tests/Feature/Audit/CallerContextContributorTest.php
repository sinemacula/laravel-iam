<?php

declare(strict_types = 1);

namespace Tests\Feature\Audit;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Failed;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Orchestra\Testbench\Attributes\DefineEnvironment;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Records\Contribution;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\PendingSnapshot;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;
use SineMacula\Laravel\Authentication\Contracts\ContextualGuard;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use SineMacula\Laravel\Iam\Audit\AuditRegistrations;
use SineMacula\Laravel\Iam\Audit\AuditSettings;
use SineMacula\Laravel\Iam\Audit\CallerContextContributor;
use SineMacula\Laravel\Iam\Audit\HeldCaller;
use SineMacula\Laravel\Iam\Audit\References;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Sso\PlainIdentity;
use Tests\TestCase;

/**
 * Feature tests for the contributor filling a record's gaps from
 * `laravel-authentication`'s caller, already resolved (IAM-9.7): it fills the
 * actor, guard, principal, tenant and session only where the record has none,
 * only while the record's actor is open or is the caller, never on a record set
 * explicitly to no one or about someone else; it walks the guards as audit-log
 * does and stops at the first holding a user, a guard that is not configured
 * being no caller; it reads only what a guard already holds, so it never
 * resolves a request's credential nor dispatches anything; it leaves a gap,
 * never throws, where a value cannot be read or recorded; and audit-log runs it
 * for every record, whatever the mappers' switch says.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CallerContextContributor::class)]
#[CoversClass(HeldCaller::class)]
#[CoversClass(AuditRegistrations::class)]
final class CallerContextContributorTest extends TestCase
{
    use MigratesMembers, SignsInPeople;

    /** @var string The code the records contributed to are given. */
    private const string CODE = 'iam_test.contributed';

    /**
     * A record with nothing set is the caller's: the actor, the guard, the
     * principal and the session are filled from the guard's bound caller, by
     * the references the mappers give them.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnOpenRecordIsFilledFromTheCaller(): void
    {
        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        $snapshot = $this->contributed(self::pending());

        self::assertEquals(Reference::to($person), $snapshot->actor);
        self::assertEquals(Reference::to($person), $snapshot->principal);
        self::assertSame(self::GUARD, $snapshot->guard);
        self::assertSame(self::keyOf($session), $snapshot->sessionId);
        self::assertNull($snapshot->tenant);
    }

    /**
     * The references follow the application's morph map, as the mappers' do.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheReferencesFollowTheMorphMap(): void
    {
        $person = $this->createPerson();

        $this->signInAndActOnSession($person);

        Relation::morphMap(['person' => Person::class]);

        try {
            $snapshot = $this->contributed(self::pending());
        } finally {
            Relation::morphMap([], false);
        }

        self::assertEquals(Reference::of('person', self::keyOf($person)), $snapshot->actor);
        self::assertEquals(Reference::of('person', self::keyOf($person)), $snapshot->principal);
    }

    /**
     * Nothing the record holds is replaced: a guard, a principal and a session
     * given or filled before stay.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNothingTheRecordHoldsIsReplaced(): void
    {
        $person = $this->createPerson();

        $this->signInAndActOnSession($person);

        $pending = self::pending()->asPrincipal(Reference::of('team', '9'));

        $pending->fillGuard('admin');
        $pending->fillSession('session-of-record');

        $snapshot = $this->contributed($pending);

        self::assertEquals(Reference::to($person), $snapshot->actor);
        self::assertEquals(Reference::of('team', '9'), $snapshot->principal);
        self::assertSame('admin', $snapshot->guard);
        self::assertSame('session-of-record', $snapshot->sessionId);
    }

    /**
     * A record whose actor is already the caller (a mapper's) gets the rest.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARecordAboutTheCallerGetsTheRest(): void
    {
        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        $snapshot = $this->contributed(self::pending()->by(Reference::to($person)));

        self::assertSame(self::GUARD, $snapshot->guard);
        self::assertSame(self::keyOf($session), $snapshot->sessionId);
        self::assertNotNull($snapshot->principal);
    }

    /**
     * A record set explicitly to no one (`by(null)`, a failed sign-in or a
     * sweep) gets nothing of the caller's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARecordAboutNoOneGetsNothing(): void
    {
        $this->signInAndActOnSession($this->createPerson());

        self::assertNothingFilled($this->contributed(self::pending()->by(null)));
    }

    /**
     * A record about someone else gets nothing of the caller's, so the caller's
     * principal, tenant or session never lands on another person's record.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARecordAboutSomeoneElseGetsNothing(): void
    {
        $this->signInAndActOnSession($this->createPerson());

        $other    = $this->createPerson();
        $snapshot = $this->contributed(self::pending()->by(Reference::to($other)));

        self::assertEquals(Reference::to($other), $snapshot->actor);
        self::assertNull($snapshot->principal);
        self::assertNull($snapshot->guard);
        self::assertNull($snapshot->sessionId);
    }

    /**
     * With no guard holding a caller, nothing is filled.
     *
     * @return void
     */
    public function testAGuestFillsNothing(): void
    {
        self::assertNothingFilled($this->contributed(self::pending()));
    }

    /**
     * It never triggers authentication: a request carrying a valid bearer token
     * for a guard that has not read it yet is left unread, so nobody is filled,
     * the guard still holds no one, and nothing is dispatched.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testItNeverTriggersAuthentication(): void
    {
        $tokens = $this->signIn($this->createPerson());

        $request = Request::create('/', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $tokens->tokens->accessToken->reveal()]);

        $this->app?->instance('request', $request);

        Auth::forgetGuards();

        $guard = Auth::guard(self::GUARD);

        self::assertInstanceOf(ContextualGuard::class, $guard);
        self::assertFalse($guard->hasUser());

        $dispatched = [];

        Event::listen([Attempting::class, Authenticated::class, Failed::class, AuthenticationEvent::class], static function (object $event) use (&$dispatched): void {
            $dispatched[] = $event::class;
        });

        self::assertNothingFilled($this->contributed(self::pending()));
        self::assertFalse($guard->hasUser());
        self::assertSame([], $dispatched);

        // The token was a caller's all along: asked itself, the guard reads it
        self::assertNotNull($guard->user());
    }

    /**
     * The guards are walked as audit-log walks them: in the order
     * `audit-log.actor.guards` lists, the first holding a user deciding.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheConfiguredGuardsAreWalkedInOrder(): void
    {
        $config = $this->app?->make('config');

        $config?->set('auth.guards.mobile', ['driver' => 'jwt', 'provider' => 'people', 'application' => ['methods' => ['password']]]);
        $config?->set('audit-log.actor.guards', ['mobile', '', self::GUARD]);

        $person = $this->createPerson();

        $this->signInAndActOnSession($person);

        $snapshot = $this->contributed(self::pending());

        self::assertEquals(Reference::to($person), $snapshot->actor);
        self::assertSame(self::GUARD, $snapshot->guard);
    }

    /**
     * The walk stops at the first guard holding a user even when it is no
     * package guard: audit-log reads that one, and a later guard, which could
     * name someone else, is never read.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheWalkStopsAtAForeignGuardHoldingAUser(): void
    {
        $config = $this->app?->make('config');

        $config?->set('auth.guards.web', ['driver' => 'session', 'provider' => 'people']);
        $config?->set('audit-log.actor.guards', ['web', self::GUARD]);

        $this->signInAndActOnSession($this->createPerson());

        Auth::guard('web')->setUser($this->createPerson());

        self::assertNothingFilled($this->contributed(self::pending()));
    }

    /**
     * A guard holding a user that is a `ContextualGuard` but no package guard
     * (`AbstractGuard`) is never read: its accessors promise nothing about
     * resolving the request, so nothing is filled, and none is asked.
     *
     * @return void
     */
    public function testAContextualGuardThatIsNoPackageGuardIsNeverRead(): void
    {
        $guard = $this->createMock(ContextualGuard::class);

        $guard->method('hasUser')->willReturn(true);
        $guard->expects(self::never())->method('identity');
        $guard->expects(self::never())->method('principal');
        $guard->expects(self::never())->method('session');
        $guard->expects(self::never())->method('tenant');
        $guard->expects(self::never())->method('user');

        Auth::extend('foreign', static fn (): ContextualGuard => $guard);
        Auth::forgetGuards();

        $config = $this->app?->make('config');

        $config?->set('auth.guards.foreign', ['driver' => 'foreign']);
        $config?->set('auth.defaults.guard', 'foreign');

        self::assertNothingFilled($this->contributed(self::pending()));
    }

    /**
     * A guard that is not configured is read as no caller, never thrown, so the
     * record is kept.
     *
     * @return void
     */
    public function testAGuardNotConfiguredIsNoCaller(): void
    {
        $this->app?->make('config')->set('audit-log.actor.guards', ['missing', self::GUARD]);

        self::assertNothingFilled($this->contributed(self::pending()));
    }

    /**
     * A default guard that is no name is read as no caller.
     *
     * @return void
     */
    public function testADefaultThatIsNoNameIsNoCaller(): void
    {
        $this->app?->make('config')->set('auth.defaults.guard', null);

        self::assertNothingFilled($this->contributed(self::pending()));
    }

    /**
     * The active tenant is named by its identifier under the mappers' one
     * tenant type, and one the guard cannot load is left open while the rest is
     * filled.
     *
     * @return void
     */
    public function testTheTenantIsNamedByItsIdentifierAndLeftOpenWhenUnavailable(): void
    {
        $person = new Person;

        $person->forceFill(['id' => 41]);

        $tenant = self::createStub(Tenant::class);
        $tenant->method('getTenantIdentifier')->willReturn('tenant-7');

        $this->useGuard($person, $tenant);

        self::assertEquals(References::tenant('tenant-7'), $this->contributed(self::pending())->tenant);

        $this->useGuard($person, new TenantUnavailableException('The tenant is gone.'));

        $snapshot = $this->contributed(self::pending());

        self::assertNull($snapshot->tenant);
        self::assertEquals(Reference::of($person->getMorphClass(), '41'), $snapshot->actor);
        self::assertSame('fixture', $snapshot->guard);
    }

    /**
     * A caller audit-log cannot refer to (an identifier beyond its columns) is
     * no caller, and a guard name or session reference it cannot store is left
     * open, so the record is kept rather than lost.
     *
     * @return void
     */
    public function testWhatCannotBeRecordedIsLeftOpen(): void
    {
        $this->useGuard(new PlainIdentity(['id' => str_repeat('9', 192)]), null);

        self::assertNothingFilled($this->contributed(self::pending()));

        $person = new Person;

        $person->forceFill(['id' => 41]);

        $name = str_repeat('g', 65);

        $this->useGuard($person, null, $name);
        $this->app?->make('config')->set('audit-log.actor.guards', [$name]);

        $snapshot = $this->contributed(self::pending());

        self::assertEquals(Reference::of($person->getMorphClass(), '41'), $snapshot->actor);
        self::assertNull($snapshot->guard);
    }

    /**
     * Registered with audit-log, it fills a record the application makes
     * itself, through audit-log's own pipeline.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testItFillsARecordThroughAuditLog(): void
    {
        $fake    = AuditLog::fake();
        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        $fake->forget();

        $record = AuditLog::record(self::CODE);

        self::assertSame($person->getMorphClass(), $record->actorType);
        self::assertSame(self::keyOf($person), $record->actorId);
        self::assertSame(self::GUARD, $record->guard);
        self::assertSame(self::keyOf($session), $record->sessionId);
        self::assertSame([$record], $fake->recorded(static fn ($recorded): bool => $recorded->event === self::CODE));
    }

    /**
     * It is registered with the mappers' switch off too: it fills the gaps of
     * any record, the application's own and those of mappers the application
     * binds itself.
     *
     * @return void
     *
     * @throws \Throwable
     */
    #[DefineEnvironment('turnTheMappersOff')]
    public function testItIsRegisteredWithTheMappersOff(): void
    {
        AuditLog::fake();

        $person = $this->createPerson();

        $this->signInAndActOnSession($person);

        $record = AuditLog::record(self::CODE);

        self::assertSame(self::keyOf($person), $record->actorId);
        self::assertSame(self::GUARD, $record->guard);
    }

    /**
     * Turn the mappers' switch off before any provider boots.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     */
    protected function turnTheMappersOff(Application $app): void
    {
        $app->make('config')->set(AuditSettings::MAPPERS, false);
    }

    /**
     * A fresh record of the tests' code, as a mapper or the application starts
     * one.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\PendingRecord
     */
    private static function pending(): PendingRecord
    {
        return (new PendingRecord)->event(self::CODE);
    }

    /**
     * The model's key, as a record holds it.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return string
     */
    private static function keyOf(Model $model): string
    {
        $key = $model->getKey();

        assert(is_int($key) || is_string($key));

        return (string) $key;
    }

    /**
     * Fail the test unless nothing of a caller's was filled.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingSnapshot  $snapshot
     * @return void
     */
    private static function assertNothingFilled(PendingSnapshot $snapshot): void
    {
        self::assertNull($snapshot->actor);
        self::assertNull($snapshot->principal);
        self::assertNull($snapshot->tenant);
        self::assertNull($snapshot->guard);
        self::assertNull($snapshot->sessionId);
    }

    /**
     * Run the contributor, as the container builds it, over the record, and
     * return what the record then holds.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $pending
     * @return \SineMacula\Laravel\AuditLog\Records\PendingSnapshot
     */
    private function contributed(PendingRecord $pending): PendingSnapshot
    {
        $contributor = $this->app?->make(CallerContextContributor::class) ?? self::fail('The application has not booted.');

        $contributor->contribute(new Contribution($pending));

        return $pending->snapshot();
    }

    /**
     * Make the default guard one holding the identity, as its own principal
     * when it is one, with no session, and the tenant given, or failing to load
     * it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Tenant|\SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException|null  $tenant
     * @param  string  $name
     * @return void
     */
    private function useGuard(Identity $identity, Tenant|TenantUnavailableException|null $tenant, string $name = 'fixture'): void
    {
        $guard = self::createStub(AbstractGuard::class);

        $guard->method('hasUser')->willReturn(true);
        $guard->method('identity')->willReturn($identity);
        $guard->method('principal')->willReturn($identity instanceof Principal ? $identity : null);
        $guard->method('session')->willReturn(null);

        if ($tenant instanceof TenantUnavailableException) {
            $guard->method('tenant')->willThrowException($tenant);
        } else {
            $guard->method('tenant')->willReturn($tenant);
        }

        Auth::extend('fixture', static fn (): ContextualGuard => $guard);
        Auth::forgetGuards();

        $config = $this->app?->make('config');

        $config?->set('auth.guards.' . $name, ['driver' => 'fixture']);
        $config?->set('auth.defaults.guard', $name);
    }
}
