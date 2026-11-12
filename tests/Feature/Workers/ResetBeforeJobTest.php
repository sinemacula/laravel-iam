<?php

declare(strict_types = 1);

namespace Tests\Feature\Workers;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Queue\Job;
use Illuminate\Contracts\Session\Session;
use Illuminate\Queue\Events\JobProcessing;
use Illuminate\Queue\Jobs\SyncJob;
use Illuminate\Support\Facades\Event;
use Orchestra\Testbench\Attributes\DefineEnvironment;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Iam\Workers\ResetBeforeJob;
use SineMacula\Laravel\Sso\Protocols\DriverScope;
use Tests\Concerns\ReadsRawListeners;
use Tests\TestCase;

/**
 * Feature tests for flushing the worker's state before each queued job.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ResetBeforeJob::class)]
final class ResetBeforeJobTest extends TestCase
{
    use ReadsRawListeners;

    /** @var string The session key the tests keep a proof record under. */
    private const string PROOFS = 'mfa-proofs';

    /**
     * The listener is registered for the queue's `JobProcessing` event.
     *
     * @return void
     */
    public function testTheListenerIsRegisteredForEachJob(): void
    {
        self::assertContains(ResetBeforeJob::class, self::rawListenersOf(JobProcessing::class));
    }

    /**
     * Each queued job starts with `laravel-authentication`'s guards reset by
     * its own listener.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEachJobResetsTheGuards(): void
    {
        $manager = \Mockery::mock(AuthManager::class);
        $manager->shouldReceive('forgetGuardState')->once();

        $this->app?->instance('auth', $manager);

        Event::dispatch(new JobProcessing('database', self::job()));
    }

    /**
     * Each queued job starts with the worker's session flushed, so it reads
     * none of the proofs `laravel-mfa`'s default proof store kept there for an
     * earlier job.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEachJobFlushesTheSession(): void
    {
        $session = $this->sessionHoldingProofs();

        (new ResetBeforeJob)(new JobProcessing('database', \Mockery::mock(Job::class)));

        self::assertSame([], $session->all());
    }

    /**
     * A job run on the `sync` connection keeps the session of the request or
     * command that dispatched it.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testASyncJobKeepsTheSession(): void
    {
        $session = $this->sessionHoldingProofs();

        (new ResetBeforeJob)(new JobProcessing('sync', new SyncJob(app(), '{}', 'sync', 'default')));

        self::assertSame(['proof'], $session->get(self::PROOFS));
    }

    /**
     * The scoped instances the queue worker forgot before fetching the job, and
     * other listeners have filled for it since, are kept.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheJobsScopedInstancesAreKept(): void
    {
        $before = $this->app?->make(DriverScope::class);

        (new ResetBeforeJob)(new JobProcessing('database', \Mockery::mock(Job::class)));

        self::assertSame($before, $this->app?->make(DriverScope::class));
    }

    /**
     * The execution frame the audit log enters as a job starts outlives the
     * reset, whatever order the listeners run in.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheAuditLogsJobFrameOutlivesTheReset(): void
    {
        Event::dispatch(new JobProcessing('database', self::job()));

        self::assertNotNull($this->app?->make(ExecutionFrames::class)->current());
    }

    /**
     * With the reset turned off, no listener is registered for jobs.
     *
     * @return void
     */
    #[DefineEnvironment('turnTheResetOff')]
    public function testTurningTheResetOffRegistersNoListener(): void
    {
        self::assertNotContains(ResetBeforeJob::class, self::rawListenersOf(JobProcessing::class));
    }

    /**
     * Turn the worker reset off.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    protected function turnTheResetOff(Application $app): void
    {
        $app->make('config')->set('iam.workers.reset', false);
    }

    /**
     * Return a queued job the audit log can name.
     *
     * @return \Illuminate\Contracts\Queue\Job
     */
    private static function job(): Job
    {
        $job = \Mockery::mock(Job::class);
        $job->shouldReceive('resolveName')->andReturn('Tests\Job');
        $job->shouldReceive('payload')->andReturn([]);

        return $job;
    }

    /**
     * Return the application's session, holding a proof record, as
     * `laravel-mfa`'s default proof store leaves one.
     *
     * @return \Illuminate\Contracts\Session\Session
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function sessionHoldingProofs(): Session
    {
        $session = $this->app?->make('session.store');

        self::assertInstanceOf(Session::class, $session);

        $session->put(self::PROOFS, ['proof']);

        return $session;
    }
}
