<?php

declare(strict_types = 1);

namespace Tests\Feature\Audit;

use Illuminate\Contracts\Auth\Guard;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Queue\WorkerOptions;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Facade;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\HeldActor;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use SineMacula\Laravel\Iam\Audit\AuthenticationActorReader;
use SineMacula\Laravel\Iam\Audit\References;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Audit\RecordsInAJob;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Resolvers\ClaimedTenant;
use Tests\TestCase;

/**
 * Feature tests for the reader that gives audit-log the caller a
 * `laravel-authentication` guard holds (IAM-9.7).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthenticationActorReader::class)]
final class AuthenticationActorReaderTest extends TestCase
{
    use MigratesMembers, SignsInPeople;

    /** @var string The queue connection the tests' jobs are queued on. */
    private const string QUEUE_CONNECTION = 'iam-jobs';

    /** @var string The code the tests record. */
    private const string CODE = 'iam_test.recorded';

    /** @var string The tenant the caller acts in. */
    private const string TENANT = 'tenant-7';

    /**
     * A record made during a request names the caller's actor, guard,
     * principal, tenant and session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequestsRecordNamesTheCaller(): void
    {
        $fake    = AuditLog::fake();
        $person  = $this->createPerson();
        $session = $this->signInActingInTenant($person);

        AuditLog::record(self::CODE);

        self::assertCaller(self::only($fake), $person, $session, self::GUARD);
    }

    /**
     * A queued job dispatched from that request records the same caller, with
     * no guard holding anyone while it runs.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAQueuedJobRecordsTheDispatchingCaller(): void
    {
        $fake    = AuditLog::fake();
        $person  = $this->createPerson();
        $session = $this->signInActingInTenant($person);

        RecordsInAJob::dispatch(self::CODE);

        $this->stopActing();
        $this->work();

        self::assertCaller(self::only($fake), $person, $session, self::GUARD);
    }

    /**
     * A record a mapper already gave the caller as its actor keeps its guard
     * and gains the principal, tenant and session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMappersActorForTheCallerGainsTheRest(): void
    {
        $fake    = AuditLog::fake();
        $person  = $this->createPerson();
        $session = $this->signInActingInTenant($person);

        AuditLog::event(self::CODE)->by(Reference::to($person))->record();

        self::assertCaller(self::only($fake), $person, $session, null);
    }

    /**
     * A guest's record names no one.
     *
     * @return void
     */
    public function testAGuestsRecordNamesNoOne(): void
    {
        $fake = AuditLog::fake();

        AuditLog::record(self::CODE);

        $record = self::only($fake);

        self::assertNull($record->actorId);
        self::assertNull($record->principalId);
        self::assertNull($record->tenantId);
        self::assertNull($record->guard);
        self::assertNull($record->sessionId);
    }

    /**
     * A guard that is none of `laravel-authentication`'s is left to audit-log.
     *
     * @return void
     */
    public function testAnotherGuardIsNotRead(): void
    {
        $guard = self::createStub(Guard::class);

        $guard->method('hasUser')->willReturn(true);

        self::assertNull(self::reader()->read('web', $guard));
    }

    /**
     * A guard holding no one is not read, and its request is never resolved.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGuardHoldingNoOneIsNeverResolved(): void
    {
        $tokens = $this->signIn($this->createPerson());

        $this->app?->instance('request', Request::create('/', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $tokens->tokens->accessToken->reveal()]));

        Auth::forgetGuards();

        $guard = Auth::guard(self::GUARD);

        self::assertNull(self::reader()->read(self::GUARD, $guard));
        self::assertFalse($guard->hasUser());
    }

    /**
     * A tenant the guard cannot load is left out, and the rest is read.
     *
     * @return void
     */
    public function testATenantThatCannotBeLoadedIsLeftOut(): void
    {
        $person = new Person;

        $person->forceFill(['id' => 41]);

        $guard = self::guardHolding($person);

        $guard->method('tenant')->willThrowException(new TenantUnavailableException('The tenant is gone.'));

        self::assertEquals(new HeldActor(Reference::of($person->getMorphClass(), '41')), self::reader()->read('fixture', $guard));
    }

    /**
     * An identity with no identifier is no actor.
     *
     * @return void
     */
    public function testAnIdentityWithNoIdentifierIsNoActor(): void
    {
        self::assertNull(self::reader()->read('fixture', self::guardHolding(new Person)));
    }

    /**
     * Run the migrations every member's tables need, and the queue's table.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void
    {
        foreach ([...self::migrationPaths(), dirname(__DIR__, 2) . '/Fixtures/database/queue'] as $path) {
            $this->loadMigrationsFrom($path);
        }
    }

    /**
     * Queue the jobs on a `database` connection of their own, so each is
     * serialised with Context and run from its payload.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $config = $app->make('config');

        $config->set('queue.default', self::QUEUE_CONNECTION);
        $config->set('queue.connections.' . self::QUEUE_CONNECTION, ['driver' => 'database', 'table' => 'iam_jobs', 'queue' => 'default', 'retry_after' => 90]);
    }

    /**
     * The reader under test.
     *
     * @return \SineMacula\Laravel\Iam\Audit\AuthenticationActorReader
     */
    private static function reader(): AuthenticationActorReader
    {
        return new AuthenticationActorReader;
    }

    /**
     * A package guard holding the identity alone.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return \PHPUnit\Framework\MockObject\Stub&\SineMacula\Laravel\Authentication\Guards\AbstractGuard
     */
    private static function guardHolding(Identity $identity): AbstractGuard
    {
        $guard = self::createStub(AbstractGuard::class);

        $guard->method('hasUser')->willReturn(true);
        $guard->method('identity')->willReturn($identity);

        return $guard;
    }

    /**
     * Sign the person in, act on the new session in the test's tenant, and
     * return the session.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return \Illuminate\Database\Eloquent\Model
     *
     * @throws \Throwable
     */
    private function signInActingInTenant(Person $person): Model
    {
        $session = $this->signInAndActOnSession($person);

        $this->actingInTenant(new ClaimedTenant(self::TENANT));

        return $session;
    }

    /**
     * Fail the test unless the record names the person, as their own principal,
     * in the test's tenant, on the session, with the guard given.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  \Illuminate\Database\Eloquent\Model  $session
     * @param  ?string  $guard
     * @return void
     */
    private static function assertCaller(AuditRecord $record, Person $person, Model $session, ?string $guard): void
    {
        self::assertSame($person->getMorphClass(), $record->actorType);
        self::assertSame(self::keyOf($person), $record->actorId);
        self::assertSame($person->getMorphClass(), $record->principalType);
        self::assertSame(self::keyOf($person), $record->principalId);
        self::assertSame(References::TENANT_TYPE, $record->tenantType);
        self::assertSame(self::TENANT, $record->tenantId);
        self::assertSame(self::keyOf($session), $record->sessionId);
        self::assertSame($guard, $record->guard);
    }

    /**
     * Run the one queued job as a queue worker does, its scoped instances and
     * facade roots forgotten first.
     *
     * @return void
     */
    private function work(): void
    {
        $app = $this->app ?? self::fail('The application has not booted.');

        self::assertSame(1, DB::table('iam_jobs')->count(), 'One job is queued.');

        $app->forgetScopedInstances();
        Facade::clearResolvedInstances();

        $app->make('queue.worker')->runNextJob(self::QUEUE_CONNECTION, 'default', new WorkerOptions);

        self::assertSame(0, DB::table('iam_jobs')->count(), 'The job ran and left the queue.');
    }

    /**
     * The one record of the tests' code the fake holds.
     *
     * @param  \SineMacula\Laravel\AuditLog\Testing\FakeAuditStore  $fake
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     */
    private static function only(FakeAuditStore $fake): AuditRecord
    {
        $records = $fake->recorded(static fn (AuditRecord $record): bool => $record->event === self::CODE);

        self::assertCount(1, $records);

        return $records[0];
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
}
