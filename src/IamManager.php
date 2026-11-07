<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam;

use Illuminate\Container\Container;
use SineMacula\Laravel\Iam\Sso\CallerScope;
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
 * Each helper hands its call to the capability's own service, resolved when it
 * is called from the application current then, never from one kept since, so
 * the manager keeps no state of its own and is safe to share across requests
 * and jobs: resolved once in a long-lived process, before Octane clones the
 * application for a request, it still resolves each service in that request's
 * own sandbox, with the request's own records. An action with a service of its
 * own (a redemption of SSO's handoff codes, a tenant's policy change, a change
 * of the tenant tree) is reached through an accessor answering that service,
 * whose one method the application calls with plain values, never through a
 * second method of the manager's that repeats it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class IamManager
{
    /**
     * Run a change that spans members in one transaction on the storage
     * connection, retrying the whole of it after a concurrency failure when no
     * transaction is open there, and return what the work returns.
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
     * The service that redeems a `sign_in` handoff code SSO issued and signs
     * the person it links in through `laravel-authentication`, in one
     * transaction (IAM-4.1).
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
     * The service that redeems a `reauthenticate` handoff code SSO issued and
     * renews the session it names through `laravel-authentication`, with one
     * write, in one transaction (IAM-4.2).
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
     * The service that redeems a `link` handoff code SSO issued, linking the
     * caller to the provider's subject through SSO's standalone redemption
     * (IAM-4.3).
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
     * The service that hands SSO's freshness contract the caller of the
     * application's own call into SSO, as a plain value, around that call
     * (IAM-4.6): SSO's management helpers and a `link` flow's start ask
     * freshness, and without a caller handed in it is `stale`.
     *
     * @return \SineMacula\Laravel\Iam\Sso\CallerScope
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function callers(): CallerScope
    {
        return self::container()->make(CallerScope::class);
    }

    /**
     * The service that applies a change of a tenant's authentication policy the
     * application reports itself, of its tenant MFA requirement or of its SSO
     * exemptions, to the sessions acting in the tenant, with the strict cut-off
     * `laravel-authentication` asks for: once in place, inside the transaction
     * that publishes the change, and once more once that commits (IAM-4.5).
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
     * The service that reports, first inside the transaction that gives a
     * person a principal, that they come to hold it, through SSO's scope
     * widening: a membership created or accepted, or a platform principal
     * created (IAM-7.3).
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
     * The service that applies a change of the application's tenant tree it
     * reports itself, a tenant moved (a child of a removed tenant included), to
     * the sessions acting in that tenant and every tenant below it, inside the
     * transaction that writes the change, after the write, and once more once
     * that commits (IAM-7.5).
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
     * Flush every member's request state between the units of work of a
     * long-lived process other than Octane's workers and the queue's, which
     * reset it themselves, once the work held for a commit that finished
     * without running it has run (`AfterConnectionCommits::settle()`): every
     * guard already resolved, the session already resolved, the scoped
     * instances the members keep request state in, and the roots the facades
     * resolved, so a facade such as `Authorization` reads the next unit's state
     * too. What the process holds for itself (Laravel's `Context`, the
     * callbacks queued with `defer()`, the audit log's execution frames) is
     * kept.
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
     * The application current now, which each service is resolved from.
     *
     * @return \Illuminate\Container\Container
     */
    private static function container(): Container
    {
        return Container::getInstance();
    }
}
