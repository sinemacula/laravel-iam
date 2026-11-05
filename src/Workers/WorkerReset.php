<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Workers;

use Illuminate\Container\Container as IlluminateContainer;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Sessions\Methods\Rehashing;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\DnsResolver;
use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Contracts\Enforcement;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Contracts\SingleUseStore;
use SineMacula\Laravel\Sso\Protocols\DriverScope;

/**
 * Flushes every member's request state, so nothing one request or job bound
 * reaches the next in a long-lived process (IAM-11.3).
 *
 * It resets every `laravel-authentication` guard already resolved to the
 * current request, creating none, and forgets the scoped instances the members
 * keep their request state in. It registers itself for Octane's workers and
 * requests and the queue's jobs, and is safe to call by hand in any other
 * long-lived process.
 *
 * Only the suite's own scoped instances are forgotten, never every one the
 * container holds: Laravel keeps a command's or a job's `Context` and its
 * deferred callbacks in scoped instances, and `laravel-audit-log` its execution
 * frames, which it enters and leaves itself as each request, command and job
 * starts and ends. A reset called between units of work in a command would
 * otherwise drop the callbacks queued with `defer()` before they ran, the
 * command's `Context` and the audit trail's command frame.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final readonly class WorkerReset
{
    /** @var list<class-string> The scoped seams `laravel-authentication` and `laravel-sso` keep request state in; `laravel-authorization`'s and this package's scoped adapters join with their milestones. */
    private const array SCOPED_STATE = [
        Rehashing::class,
        SingleUseStore::class,
        SecretEncrypter::class,
        Fetcher::class,
        AttemptLimiter::class,
        DnsResolver::class,
        Enforcement::class,
        EndpointResolver::class,
        HandoffIssuer::class,
        DriverScope::class,
    ];

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The application whose request state is flushed. */
        private Container $container,
    ) {}

    /**
     * Flush every member's request state: the guards and the scoped instances
     * the members keep it in.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function reset(): void
    {
        $this->forgetMemberState();
        $this->forgetScopedState();
    }

    /**
     * Flush the request state the members keep outside scoped instances, and
     * leave every scoped instance where it is.
     *
     * A queue worker forgets the scoped instances itself before it fetches each
     * job, and Octane clones each request's sandbox from an application whose
     * scoped instances it forgets once each operation ends; by the time a job's
     * or a request's listeners run, others among them have already filled
     * scoped instances for it (the audit log's job frame, the request's
     * `Context`), which a second flush would discard. Every
     * `laravel-authentication` guard already resolved is reset to the current
     * request; the auth manager is not built when nothing has resolved it,
     * since no guard can hold state then.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function forgetMemberState(): void
    {
        if (!$this->container->resolved('auth')) {
            return;
        }

        $auth = $this->container->make('auth');

        // An application may bind another manager to `auth`, whatever the
        // installed members bind.
        // @phpstan-ignore instanceof.alwaysTrue
        if (!$auth instanceof AuthManager) {
            return;
        }

        $auth->forgetGuardState();
    }

    /**
     * Forget the scoped instances the members keep their request state in, when
     * the container can forget an instance, so the next unit of work builds its
     * own; every other scoped instance is kept.
     *
     * @return void
     */
    private function forgetScopedState(): void
    {
        if (!$this->container instanceof IlluminateContainer) {
            return;
        }

        foreach (self::SCOPED_STATE as $abstract) {
            $this->container->forgetInstance($abstract);
        }
    }
}
