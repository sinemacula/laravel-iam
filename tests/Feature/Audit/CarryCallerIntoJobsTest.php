<?php

declare(strict_types = 1);

namespace Tests\Feature\Audit;

use Illuminate\Contracts\Queue\Job;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Events\Dispatcher;
use Illuminate\Log\Context\Repository;
use Illuminate\Queue\Events\JobExceptionOccurred;
use Illuminate\Queue\Events\JobFailed;
use Illuminate\Queue\Events\JobProcessed;
use Illuminate\Queue\Events\JobProcessing;
use Illuminate\Queue\WorkerOptions;
use Illuminate\Support\Facades\Context;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Facade;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;
use SineMacula\Laravel\Iam\Audit\CallerContextContributor;
use SineMacula\Laravel\Iam\Audit\CallerSnapshot;
use SineMacula\Laravel\Iam\Audit\CarryCallerIntoJobs;
use SineMacula\Laravel\Iam\Audit\HeldCaller;
use SineMacula\Laravel\Iam\Audit\JobCallers;
use SineMacula\Laravel\Iam\Bindings\BindingRule;
use SineMacula\Laravel\Iam\IamManager;
use SineMacula\Laravel\Iam\IamServiceProvider;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Audit\RecordsInAJob;
use Tests\Fixtures\Providers\RecordsAJobsEnd;
use Tests\TestCase;

/**
 * Feature tests for the caller carried into a queued job (IAM-9.7), run as a
 * queue worker runs it: a record the job leaves to the caller is attributed to
 * the `laravel-authentication` caller who dispatched it, which audit-log's own
 * carried actor cannot name, with the guard, principal and session the caller
 * held; a job it dispatches carries the same caller on, unless the job binds a
 * caller of its own, which beats it; a guest's job carries none, and a caller a
 * sync job left in Context is not sent on; a record an application's provider
 * makes of a job's end is still the carried caller's, and so is one made after
 * the explicit worker reset inside the job; and once the job has ended, on
 * success or on failure, its caller is no record's.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CarryCallerIntoJobs::class)]
#[CoversClass(CallerContextContributor::class)]
#[CoversClass(HeldCaller::class)]
#[CoversClass(IamServiceProvider::class)]
final class CarryCallerIntoJobsTest extends TestCase
{
    use MigratesMembers, SignsInPeople;

    /** @var string The queue connection the tests' jobs are queued on. */
    private const string QUEUE_CONNECTION = 'iam-jobs';

    /** @var string The code the job records. */
    private const string CODE = 'iam_test.in_a_job';

    /** @var string The code a job the first dispatches records. */
    private const string CHAINED = 'iam_test.chained';

    /** @var string The code recorded once the jobs have ended. */
    private const string AFTER = 'iam_test.after_the_job';

    /**
     * A record a queued job leaves to the caller is the dispatching caller's,
     * signed in on the `jwt` guard: the actor, the guard, the principal and the
     * session the caller held as it dispatched the job.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACallerRecordInAQueuedJobIsTheDispatchingCallers(): void
    {
        $fake    = AuditLog::fake();
        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        RecordsInAJob::dispatch(self::CODE);

        $this->work();

        $record = self::only($fake, self::CODE);

        self::assertSame($person->getMorphClass(), $record->actorType);
        self::assertSame(self::keyOf($person), $record->actorId);
        self::assertSame($person->getMorphClass(), $record->principalType);
        self::assertSame(self::keyOf($person), $record->principalId);
        self::assertSame(self::GUARD, $record->guard);
        self::assertSame(self::keyOf($session), $record->sessionId);
    }

    /**
     * A job a queued job dispatches carries the caller the first carried, so a
     * chain of jobs keeps naming who started it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAJobDispatchedFromAJobCarriesTheCallerOn(): void
    {
        $fake   = AuditLog::fake();
        $person = $this->createPerson();

        $this->signInAndActOnSession($person);

        RecordsInAJob::dispatch(self::CODE, self::CHAINED);

        $this->work();
        $this->work();

        $record = self::only($fake, self::CHAINED);

        self::assertSame(self::keyOf($person), $record->actorId);
        self::assertSame(self::GUARD, $record->guard);
    }

    /**
     * A job a guest dispatched carries no caller, so its record names none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGuestsJobCarriesNoCaller(): void
    {
        $fake = AuditLog::fake();

        RecordsInAJob::dispatch(self::CODE);

        self::assertNull(self::carriedBy(self::queuedPayload()));

        $this->work();

        $record = self::only($fake, self::CODE);

        self::assertNull($record->actorId);
        self::assertNull($record->guard);
        self::assertNull($record->sessionId);
    }

    /**
     * Once the job has ended, the caller it carried is no record's: a record
     * made after it, with no guard holding a caller, names no one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheCarriedCallerEndsWithItsJob(): void
    {
        $fake = AuditLog::fake();

        $this->signInAndActOnSession($this->createPerson());

        RecordsInAJob::dispatch(self::CODE);

        $this->work();

        self::assertNotNull(self::only($fake, self::CODE)->actorId);

        AuditLog::record(self::AFTER);

        $record = self::only($fake, self::AFTER);

        self::assertNull($record->actorId);
        self::assertNull($record->guard);
    }

    /**
     * A caller a sync job left in Context, with no guard holding a caller now,
     * is not sent on in the next job's payload, and Context keeps it.
     *
     * @return void
     */
    public function testACallerLeftInContextIsNotSentOn(): void
    {
        (new CallerSnapshot(self::GUARD, 'person', '7'))->carryInto(app(Repository::class));

        RecordsInAJob::dispatch(self::CODE);

        self::assertNull(self::carriedBy(self::queuedPayload()));
        self::assertNotNull(Context::getHidden(CallerSnapshot::KEY));
    }

    /**
     * The payload carries the caller under its one hidden key, beside
     * audit-log's own envelope, which names no actor of a package guard's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThePayloadCarriesTheCallerBesideAuditLogsEnvelope(): void
    {
        $person  = $this->createPerson();
        $session = $this->signInAndActOnSession($person);

        RecordsInAJob::dispatch(self::CODE);

        $payload = self::queuedPayload();
        $type    = $person->getMorphClass();
        $id      = self::keyOf($person);

        self::assertEquals(new CallerSnapshot(self::GUARD, $type, $id, $type, $id, null, self::keyOf($session)), self::carriedBy($payload));
        self::assertFalse(self::contextOf($payload)->hasHidden('audit-log.actor_id'));
    }

    /**
     * Guards that cannot be read (one configured with a driver that cannot be
     * built) carry no caller, not even one a sync job left in Context, and
     * never stop the job being queued.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGuardThatCannotBeBuiltStillQueuesTheJob(): void
    {
        $this->signInAndActOnSession($this->createPerson());

        (new CallerSnapshot(self::GUARD, 'person', '7'))->carryInto(app(Repository::class));

        $config = $this->app?->make('config');

        $config?->set('auth.guards.unbuildable', ['driver' => 'no-such-driver']);
        $config?->set('audit-log.actor.guards', ['unbuildable', self::GUARD]);

        RecordsInAJob::dispatch(self::CODE);

        self::assertNull(self::carriedBy(self::queuedPayload()));
    }

    /**
     * A caller a job binds on a guard itself beats the caller it carried, for
     * its own records and for the jobs it dispatches: it says who did the work.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACallerTheJobBindsItselfBeatsTheCarriedOne(): void
    {
        AuditLog::fake();

        Event::dispatch(new JobProcessing(self::QUEUE_CONNECTION, self::jobCarrying(new CallerSnapshot(self::GUARD, 'person', '999'))));

        $person = $this->createPerson();

        $this->signInAndActOnSession($person);

        self::assertSame(self::keyOf($person), AuditLog::record(self::CODE)->actorId);

        RecordsInAJob::dispatch(self::CHAINED);

        self::assertSame(self::keyOf($person), self::carriedBy(self::queuedPayload())?->identityId);
    }

    /**
     * Provide each way a job ends.
     *
     * @return iterable<string, array{\Closure(\Illuminate\Contracts\Queue\Job): object}>
     */
    public static function provideJobEnds(): iterable
    {
        yield 'processed' => [static fn (Job $job): object => new JobProcessed(self::QUEUE_CONNECTION, $job)];
        yield 'failed' => [static fn (Job $job): object => new JobFailed(self::QUEUE_CONNECTION, $job, new \RuntimeException('Failed.'))];
        yield 'an exception' => [static fn (Job $job): object => new JobExceptionOccurred(self::QUEUE_CONNECTION, $job, new \RuntimeException('Failed.'))];
    }

    /**
     * A job's frame is left as it ends, however it ends, so its caller is no
     * later record's.
     *
     * @param  \Closure(\Illuminate\Contracts\Queue\Job): object  $end
     * @return void
     */
    #[DataProvider('provideJobEnds')]
    public function testAJobsFrameIsLeftHoweverItEnds(\Closure $end): void
    {
        $caller = new CallerSnapshot(self::GUARD, 'person', '7');
        $job    = self::jobCarrying($caller);

        Event::dispatch(new JobProcessing(self::QUEUE_CONNECTION, $job));

        self::assertEquals($caller, $this->jobCallers()->current());

        Event::dispatch($end($job));

        self::assertNull($this->jobCallers()->current());
    }

    /**
     * A record an application's provider, booted after this package's, makes as
     * a queued job ends is the dispatching caller's: the job's frame is left
     * only after every listener any provider's `boot()` adds, as audit-log's
     * own job frame is.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARecordOfAQueuedJobsEndIsTheDispatchingCallers(): void
    {
        $fake   = AuditLog::fake();
        $person = $this->createPerson();

        $this->signInAndActOnSession($person);

        RecordsInAJob::dispatch(self::CODE);

        $this->work();

        $record = self::only($fake, RecordsAJobsEnd::CODE);

        self::assertSame(self::keyOf($person), $record->actorId);
        self::assertSame(self::GUARD, $record->guard);
        self::assertSame('queue', $record->origin);
    }

    /**
     * However a job ends, the record an application's provider makes of its end
     * is the caller the job carried, and the frame is left after it.
     *
     * @param  \Closure(\Illuminate\Contracts\Queue\Job): object  $end
     * @return void
     */
    #[DataProvider('provideJobEnds')]
    public function testARecordOfAJobsEndIsTheCarriedCallersHoweverItEnds(\Closure $end): void
    {
        $fake = AuditLog::fake();
        $job  = self::jobCarrying(new CallerSnapshot(self::GUARD, 'person', '7'));

        Event::dispatch(new JobProcessing(self::QUEUE_CONNECTION, $job));
        Event::dispatch($end($job));

        self::assertSame('7', self::only($fake, RecordsAJobsEnd::CODE)->actorId);
        self::assertNull($this->jobCallers()->current());
    }

    /**
     * The explicit worker reset, called between a job's own units of work,
     * keeps the caller the job carried: the records after it and the jobs it
     * dispatches after it are still the caller's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResetInsideAJobKeepsTheCarriedCaller(): void
    {
        AuditLog::fake();

        Event::dispatch(new JobProcessing(self::QUEUE_CONNECTION, self::jobCarrying(new CallerSnapshot(self::GUARD, 'person', '7'))));

        self::assertSame('7', AuditLog::record(self::CODE)->actorId);

        $this->app?->make(IamManager::class)->resetWorkerState();

        $record = AuditLog::record(self::AFTER);

        self::assertSame('7', $record->actorId);
        self::assertSame(self::GUARD, $record->guard);

        RecordsInAJob::dispatch(self::CHAINED);

        self::assertSame('7', self::carriedBy(self::queuedPayload())?->identityId);
    }

    /**
     * The frames of the jobs running are scoped under their own class, outside
     * this package's key for scoped adapters: the explicit worker reset keeps
     * them, and the scoped instances the queue worker and Octane forget between
     * jobs and requests take them.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheJobCallersAreScopedAndKeptByTheExplicitReset(): void
    {
        $app     = $this->app ?? self::fail('The application has not booted.');
        $callers = $this->jobCallers();

        self::assertSame($callers, $this->jobCallers());
        self::assertFalse($app->bound(BindingRule::SCOPED_PREFIX . JobCallers::class));

        $app->make(IamManager::class)->resetWorkerState();

        self::assertSame($callers, $this->jobCallers());

        $app->forgetScopedInstances();

        self::assertNotSame($callers, $this->jobCallers());
    }

    /**
     * Register every member's provider and this package's, then an
     * application's provider recording each job's end, booted after them.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return list<class-string<\Illuminate\Support\ServiceProvider>>
     */
    #[\Override]
    protected function getPackageProviders(mixed $app): array
    {
        return [...parent::getPackageProviders($app), RecordsAJobsEnd::class];
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
     * Run the next queued job as a queue worker does: the scoped instances and
     * the facades' resolved instances forgotten first, as the worker's own
     * scope reset forgets them before it fetches each job, then the job run
     * from its payload, which every member's worker reset precedes. The job
     * must leave the queue having run.
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

        self::assertSame(0, DB::table('iam_jobs')->where('attempts', '>', 0)->count(), 'The job ran once and left the queue.');
    }

    /**
     * The record of the callers queued jobs carried, as the application current
     * builds it.
     *
     * @return \SineMacula\Laravel\Iam\Audit\JobCallers
     */
    private function jobCallers(): JobCallers
    {
        return $this->app?->make(JobCallers::class) ?? self::fail('The application has not booted.');
    }

    /**
     * The payload of the one job queued.
     *
     * @return array<string, mixed>
     */
    private static function queuedPayload(): array
    {
        $encoded = DB::table('iam_jobs')->value('payload');

        self::assertIsString($encoded);

        $payload = json_decode($encoded, true);

        self::assertIsArray($payload);

        /** @var array<string, mixed> $payload */
        return $payload;
    }

    /**
     * The caller a job's payload carries, read back as the job reads it.
     *
     * @param  array<string, mixed>  $payload
     * @return ?\SineMacula\Laravel\Iam\Audit\CallerSnapshot
     */
    private static function carriedBy(array $payload): ?CallerSnapshot
    {
        return CallerSnapshot::carriedIn(self::contextOf($payload));
    }

    /**
     * The Context a job's payload carries, read back as the job reads it.
     *
     * @param  array<string, mixed>  $payload
     * @return \Illuminate\Log\Context\Repository
     */
    private static function contextOf(array $payload): Repository
    {
        $context = new Repository(new Dispatcher);

        $context->hydrate(is_array($payload['illuminate:log:context'] ?? null) ? $payload['illuminate:log:context'] : null);

        return $context;
    }

    /**
     * A queued job whose payload carries the caller.
     *
     * @param  \SineMacula\Laravel\Iam\Audit\CallerSnapshot  $caller
     * @return \Illuminate\Contracts\Queue\Job
     */
    private static function jobCarrying(CallerSnapshot $caller): Job
    {
        $context = new Repository(new Dispatcher);

        $caller->carryInto($context);

        $job = \Mockery::mock(Job::class);

        $job->shouldReceive('resolveName')->andReturn(RecordsInAJob::class);
        $job->shouldReceive('payload')->andReturn(['illuminate:log:context' => $context->dehydrate()]);

        return $job;
    }

    /**
     * The one record of the code the fake holds.
     *
     * @param  \SineMacula\Laravel\AuditLog\Testing\FakeAuditStore  $fake
     * @param  string  $code
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     */
    private static function only(FakeAuditStore $fake, string $code): AuditRecord
    {
        $records = $fake->recorded(static fn (AuditRecord $record): bool => $record->event === $code);

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
