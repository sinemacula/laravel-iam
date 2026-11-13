<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Console\Application as Artisan;
use Illuminate\Console\Scheduling\Event as ScheduledEvent;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Database\DeadlockException;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Contracts\PolicyResolver;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\DecisionProvenance;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\LastDecisionStore;
use SineMacula\Laravel\Authorization\Evaluation\PolicyEvaluator;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\IamManager;
use SineMacula\Laravel\Iam\Scheduling\IamSchedule;
use SineMacula\Laravel\Iam\Sso\Callers;
use SineMacula\Laravel\Iam\Sso\LinkRedemption;
use SineMacula\Laravel\Iam\Sso\ReauthenticationRedemption;
use SineMacula\Laravel\Iam\Sso\SignInRedemption;
use SineMacula\Laravel\Iam\Tenancy\ScopeWidenings;
use SineMacula\Laravel\Iam\Tenancy\TenantPolicyChanges;
use SineMacula\Laravel\Iam\Tenancy\TreeChanges;
use SineMacula\Laravel\Sso\Exceptions\LinkCandidatesChanged;
use SineMacula\Laravel\Sso\Protocols\DriverScope;
use Tests\Concerns\RunsInOctaneSandboxes;
use Tests\TestCase;

/**
 * Feature tests for the services the `Iam` facade calls.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IamManager::class)]
final class IamManagerTest extends TestCase
{
    use RunsInOctaneSandboxes;

    /**
     * A transaction runs the work on the storage connection and returns its
     * result.
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
     * A transaction is attempted as often as the configuration says.
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
     * Attempts given replace the configured ones.
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
     * Each redemption has its own service, resolved afresh each time.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEachRedemptionIsReachedThroughItsOwnService(): void
    {
        $manager = $this->manager();

        self::assertInstanceOf(SignInRedemption::class, $manager->signIns());
        self::assertInstanceOf(ReauthenticationRedemption::class, $manager->reauthentications());
        self::assertInstanceOf(LinkRedemption::class, $manager->links());
        self::assertNotSame($manager->signIns(), $manager->signIns());
        self::assertNotSame($manager->reauthentications(), $manager->reauthentications());
        self::assertNotSame($manager->links(), $manager->links());
    }

    /**
     * The callers service is resolved on each call.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheCallersAreNamedThroughTheirOwnService(): void
    {
        $manager = $this->manager();

        self::assertInstanceOf(Callers::class, $manager->callers());
        self::assertNotSame($manager->callers(), $manager->callers());
    }

    /**
     * The tenant policy service is resolved on each call.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheTenantPolicyChangesAreReachedThroughTheirOwnService(): void
    {
        $manager = $this->manager();

        self::assertInstanceOf(TenantPolicyChanges::class, $manager->tenantPolicies());
        self::assertNotSame($manager->tenantPolicies(), $manager->tenantPolicies());
    }

    /**
     * The scope widening service is resolved on each call.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheScopeWideningsAreReachedThroughTheirOwnService(): void
    {
        $manager = $this->manager();

        self::assertInstanceOf(ScopeWidenings::class, $manager->scopeWidenings());
        self::assertNotSame($manager->scopeWidenings(), $manager->scopeWidenings());
    }

    /**
     * The tree change service is resolved on each call.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheTreeChangesAreReachedThroughTheirOwnService(): void
    {
        $manager = $this->manager();

        self::assertInstanceOf(TreeChanges::class, $manager->treeChanges());
        self::assertNotSame($manager->treeChanges(), $manager->treeChanges());
    }

    /**
     * The members' scheduled work is registered on the schedule handed in.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheScheduleIsRegisteredOnTheScheduleHandedIn(): void
    {
        $schedule = new Schedule;

        $this->manager()->schedule($schedule);

        self::assertSame(
            [Artisan::formatCommandString(IamSchedule::MFA_PRUNE), Artisan::formatCommandString(IamSchedule::AUTHORIZATION_PRUNE)],
            array_map(static fn (ScheduledEvent $event): ?string => $event->command, $schedule->events()),
        );
    }

    /**
     * A manager resolved before Octane clones the app resolves in the sandbox.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEachServiceIsResolvedFromTheCurrentApplication(): void
    {
        $manager = $this->manager();

        $this->app?->make('iam');

        $this->inOctaneSandbox(function (Application $sandbox) use ($manager): void {

            $signIns  = $sandbox->make(SignInRedemption::class);
            $links    = $sandbox->make(LinkRedemption::class);
            $renewals = $sandbox->make(ReauthenticationRedemption::class);
            $changes  = $sandbox->make(TenantPolicyChanges::class);
            $widening = $sandbox->make(ScopeWidenings::class);
            $tree     = $sandbox->make(TreeChanges::class);
            $callers  = $sandbox->make(Callers::class);

            $sandbox->instance(SignInRedemption::class, $signIns);
            $sandbox->instance(LinkRedemption::class, $links);
            $sandbox->instance(ReauthenticationRedemption::class, $renewals);
            $sandbox->instance(TenantPolicyChanges::class, $changes);
            $sandbox->instance(ScopeWidenings::class, $widening);
            $sandbox->instance(TreeChanges::class, $tree);
            $sandbox->instance(Callers::class, $callers);

            self::assertSame($manager, $sandbox->make('iam'));
            self::assertSame($signIns, $manager->signIns());
            self::assertSame($signIns, Iam::signIns());
            self::assertSame($links, Iam::links());
            self::assertSame($renewals, Iam::reauthentications());
            self::assertSame($changes, Iam::tenantPolicies());
            self::assertSame($widening, Iam::scopeWidenings());
            self::assertSame($tree, Iam::treeChanges());
            self::assertSame($callers, Iam::callers());
        });
    }

    /**
     * A redemption service the application binds is the one answered.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheApplicationsRedemptionServiceIsAnswered(): void
    {
        $signIns = $this->app?->make(SignInRedemption::class);

        $this->app?->instance(SignInRedemption::class, $signIns);

        self::assertSame($signIns, $this->manager()->signIns());
    }

    /**
     * The worker reset resets the guards and forgets the scoped instances.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testResettingTheWorkerStateFlushesEveryMembersRequestState(): void
    {
        $auth = \Mockery::mock(AuthManager::class);
        $auth->shouldReceive('forgetGuardState')->once();

        $this->app?->instance('auth', $auth);

        $before = $this->app?->make(DriverScope::class);

        $this->manager()->resetWorkerState();

        self::assertNotSame($before, $this->app?->make(DriverScope::class));
    }

    /**
     * The worker reset forgets laravel-authorization's request state.
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
     * The worker reset forgets the decision the `Authorization` facade holds.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testResettingTheWorkerStateForgetsTheDecisionTheAuthorizationFacadeHolds(): void
    {
        Authorization::getFacadeRoot();

        $this->app?->make(LastDecisionStore::class)->put(Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT), new DecisionProvenance);

        self::assertNotNull(Authorization::lastDecision());

        $this->manager()->resetWorkerState();

        self::assertNull($this->app?->make('authorization')->lastDecision());
        self::assertNull(Authorization::lastDecision());
    }

    /**
     * How many times always-retryable work runs before its failure is rethrown.
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
        } catch (DeadlockException $exception) {
            self::assertInstanceOf(LinkCandidatesChanged::class, $exception->getPrevious());
        }

        return $runs;
    }

    /**
     * The manager the facade calls.
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
