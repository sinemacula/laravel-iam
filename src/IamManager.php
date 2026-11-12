<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam;

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Container\Container;
use SineMacula\Laravel\Iam\Scheduling\IamSchedule;
use SineMacula\Laravel\Iam\Sso\Callers;
use SineMacula\Laravel\Iam\Sso\LinkRedemption;
use SineMacula\Laravel\Iam\Sso\ReauthenticationRedemption;
use SineMacula\Laravel\Iam\Sso\SignInRedemption;
use SineMacula\Laravel\Iam\Tenancy\ScopeWidenings;
use SineMacula\Laravel\Iam\Tenancy\TenantPolicyChanges;
use SineMacula\Laravel\Iam\Tenancy\TreeChanges;
use SineMacula\Laravel\Iam\Transactions\CrossMemberTransaction;
use SineMacula\Laravel\Iam\Workers\WorkerReset;

/**
 * The services an application calls through the `Iam` facade.
 *
 * Each is resolved from the current container on every call, so the manager
 * holds no state and is safe under Octane.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class IamManager
{
    /**
     * Run a cross-member change in one transaction, retried only when
     * outermost.
     *
     * @template T
     *
     * @param  \Closure(): T  $work
     * @param  ?int  $attempts
     * @return T
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    public function transaction(\Closure $work, ?int $attempts = null): mixed
    {
        return self::container()->make(CrossMemberTransaction::class)->run($work, $attempts);
    }

    /**
     * The service that redeems SSO's `sign_in` handoff codes.
     *
     * @return \SineMacula\Laravel\Iam\Sso\SignInRedemption
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function signIns(): SignInRedemption
    {
        return self::container()->make(SignInRedemption::class);
    }

    /**
     * The service that redeems SSO's `reauthenticate` handoff codes.
     *
     * @return \SineMacula\Laravel\Iam\Sso\ReauthenticationRedemption
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function reauthentications(): ReauthenticationRedemption
    {
        return self::container()->make(ReauthenticationRedemption::class);
    }

    /**
     * The service that redeems SSO's `link` handoff codes.
     *
     * @return \SineMacula\Laravel\Iam\Sso\LinkRedemption
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function links(): LinkRedemption
    {
        return self::container()->make(LinkRedemption::class);
    }

    /**
     * The service that names the caller of the application's own calls into
     * SSO.
     *
     * @return \SineMacula\Laravel\Iam\Sso\Callers
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function callers(): Callers
    {
        return self::container()->make(Callers::class);
    }

    /**
     * The service that applies a tenant's authentication policy change.
     *
     * @return \SineMacula\Laravel\Iam\Tenancy\TenantPolicyChanges
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function tenantPolicies(): TenantPolicyChanges
    {
        return self::container()->make(TenantPolicyChanges::class);
    }

    /**
     * The service that reports a person coming to hold a principal.
     *
     * @return \SineMacula\Laravel\Iam\Tenancy\ScopeWidenings
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function scopeWidenings(): ScopeWidenings
    {
        return self::container()->make(ScopeWidenings::class);
    }

    /**
     * The service that applies a tenant moved within the tenant tree.
     *
     * @return \SineMacula\Laravel\Iam\Tenancy\TreeChanges
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function treeChanges(): TreeChanges
    {
        return self::container()->make(TreeChanges::class);
    }

    /**
     * Register the members' scheduled work they leave to the application.
     *
     * @param  \Illuminate\Console\Scheduling\Schedule  $schedule
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function schedule(Schedule $schedule): void
    {
        self::container()->make(IamSchedule::class)->register($schedule);
    }

    /**
     * Flush request state in a long-lived process other than Octane or queues.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function resetWorkerState(): void
    {
        self::container()->make(WorkerReset::class)->reset();
    }

    /**
     * The current container.
     *
     * @return \Illuminate\Container\Container
     */
    private static function container(): Container
    {
        return Container::getInstance();
    }
}
