<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Iam\Sso\LinkRedemption;
use SineMacula\Laravel\Iam\Sso\ReauthenticationRedemption;
use SineMacula\Laravel\Iam\Sso\SignInRedemption;
use SineMacula\Laravel\Iam\Transactions\CrossMemberTransaction;
use SineMacula\Laravel\Iam\Workers\WorkerReset;

/**
 * The services an application calls through the `Iam` facade.
 *
 * Each helper hands its call to the capability's own service, resolved when it
 * is called, so the manager keeps no state of its own and is safe to share
 * across requests and jobs. An action with a service of its own (a redemption
 * of SSO's handoff codes) is reached through an accessor answering that
 * service, whose one method the application calls with plain values, never
 * through a second method of the manager's that repeats it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class IamManager
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The application each capability's service is resolved from. */
        private Container $container,
    ) {}

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
        return $this->container->make(CrossMemberTransaction::class)->run($work, $attempts);
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
        return $this->container->make(SignInRedemption::class);
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
        return $this->container->make(ReauthenticationRedemption::class);
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
        return $this->container->make(LinkRedemption::class);
    }

    /**
     * Flush every member's request state between the units of work of a
     * long-lived process other than Octane's workers and the queue's, which
     * reset it themselves: every guard already resolved, the session already
     * resolved, the scoped instances the members keep request state in, and the
     * roots the facades resolved, so a facade such as `Authorization` reads the
     * next unit's state too. What the process holds for itself (Laravel's
     * `Context`, the callbacks queued with `defer()`, the audit log's execution
     * frames) is kept.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function resetWorkerState(): void
    {
        $this->container->make(WorkerReset::class)->reset();
    }
}
