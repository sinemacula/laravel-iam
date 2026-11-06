<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Console\Events\CommandFinished;
use Illuminate\Console\Events\CommandStarting;
use Illuminate\Support\Facades\Context;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Contracts\PolicyResolver;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\LastDecisionStore;
use SineMacula\Laravel\Authorization\Evaluation\PolicyEvaluator;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use SineMacula\Laravel\Iam\IamManager;
use SineMacula\Laravel\Sso\Exceptions\LinkCandidatesChanged;
use SineMacula\Laravel\Sso\Protocols\DriverScope;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\NullOutput;
use Tests\TestCase;

/**
 * Feature tests for the services the `Iam` facade calls: each helper hands its
 * call to the capability's own service.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IamManager::class)]
final class IamManagerTest extends TestCase
{
    /**
     * A cross-member transaction runs the work in one transaction on the
     * storage connection and returns what it returns.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheTransactionRunsTheWorkInOneTransaction(): void
    {
        $level = $this->manager()->transaction(static fn (): int => DB::connection()->transactionLevel());

        self::assertSame(1, $level);
        self::assertSame(0, DB::connection()->transactionLevel());
    }

    /**
     * Without attempts of its own, the transaction is attempted as often as the
     * configuration says before its failure is rethrown.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheTransactionIsAttemptedAsTheConfigurationSays(): void
    {
        $this->app?->make('config')->set('iam.transactions.attempts', 4);

        self::assertSame(4, $this->failingRuns(null));
    }

    /**
     * The attempts given are passed on, in place of the configured ones.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheAttemptsGivenArePassedOn(): void
    {
        self::assertSame(2, $this->failingRuns(2));
    }

    /**
     * Resetting the worker state resets `laravel-authentication`'s guards and
     * forgets the members' scoped instances.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testResettingTheWorkerStateFlushesEveryMembersRequestState(): void
    {
        $auth = \Mockery::mock(AuthManager::class);
        $auth->shouldReceive('setApplication')->once()->with($this->app)->ordered()->andReturnSelf();
        $auth->shouldReceive('forgetGuardState')->once()->ordered();

        $this->app?->instance('auth', $auth);

        $before = $this->app?->make(DriverScope::class);

        $this->manager()->resetWorkerState();

        self::assertNotSame($before, $this->app?->make(DriverScope::class));
    }

    /**
     * Resetting the worker state forgets `laravel-authorization`'s request
     * state as the member binds it: the resolved tenant, the resolution cache,
     * the last decision, the policy evaluator, the manager and the defaults
     * behind its resolvers are each built afresh for the next unit of work.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testResettingTheWorkerStateForgetsTheAuthorizationRequestState(): void
    {
        $abstracts = [
            ResolvedTenant::class,
            ResolutionCache::class,
            LastDecisionStore::class,
            PolicyEvaluator::class,
            'authorization',
            SubjectResolver::class,
            PolicyResolver::class,
        ];
        $before = array_map(fn (string $abstract): mixed => $this->app?->make($abstract), $abstracts);

        $this->manager()->resetWorkerState();

        foreach ($abstracts as $index => $abstract) {
            self::assertNotSame($before[$index], $this->app?->make($abstract), $abstract . ' was kept.');
        }
    }

    /**
     * Resetting the worker state forgets the last decision read through
     * `laravel-authorization`'s `Authorization` facade, which keeps the manager
     * it first resolved, as well as the one the container holds.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testResettingTheWorkerStateForgetsTheDecisionTheAuthorizationFacadeHolds(): void
    {
        Authorization::getFacadeRoot();

        $this->app?->make(LastDecisionStore::class)->put(Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT));

        self::assertNotNull(Authorization::lastDecision());

        $this->manager()->resetWorkerState();

        self::assertNull($this->app?->make('authorization')->lastDecision());
        self::assertNull(Authorization::lastDecision());
    }

    /**
     * Reset by hand between the units of work of a long-running command, the
     * worker state keeps what the command itself holds: the callbacks it queued
     * with `defer()` still run as it finishes, its `Context` is kept, and the
     * audit log's command frame is still the current one.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testResettingTheWorkerStateByHandKeepsWhatTheCommandHolds(): void
    {
        $input  = new ArrayInput([]);
        $output = new NullOutput;

        /** @var \ArrayObject<int, int> $ran */
        $ran = new \ArrayObject([]);

        Event::dispatch(new CommandStarting('app:daemon', $input, $output));
        Context::add('trace', 'abc');

        foreach ([1, 2] as $unit) {

            defer(static function () use ($ran, $unit): void {
                $ran[] = $unit;
            });

            $this->manager()->resetWorkerState();
        }

        self::assertSame('abc', Context::get('trace'));
        self::assertNotNull($this->app?->make(ExecutionFrames::class)->current());
        self::assertSame([], $ran->getArrayCopy());

        Event::dispatch(new CommandFinished('app:daemon', $input, $output, 0));

        self::assertSame([1, 2], $ran->getArrayCopy());
    }

    /**
     * Run work that always fails with a retryable failure, and return how many
     * times it ran before the failure was rethrown.
     *
     * @param  ?int  $attempts
     * @return int
     *
     * @throws \Throwable
     */
    private function failingRuns(?int $attempts): int
    {
        $runs = 0;

        try {
            $this->manager()->transaction(static function () use (&$runs): never {

                $runs++;

                throw LinkCandidatesChanged::retryWhole();
            }, $attempts);
        } catch (LinkCandidatesChanged) {
            // The last attempt's failure is rethrown; only the runs matter.
        }

        return $runs;
    }

    /**
     * Return the manager the facade calls.
     *
     * @return \SineMacula\Laravel\Iam\IamManager
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function manager(): IamManager
    {
        $manager = $this->app?->make(IamManager::class);

        self::assertInstanceOf(IamManager::class, $manager);

        return $manager;
    }
}
