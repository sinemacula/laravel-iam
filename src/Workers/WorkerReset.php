<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Workers;

use Illuminate\Container\Container;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Session\Session;
use Illuminate\Support\Facades\Facade;
use SineMacula\Laravel\Authentication\Database\RequiredWork;
use SineMacula\Laravel\Authentication\Sessions\KeptSessions;
use SineMacula\Laravel\Authentication\Sessions\Methods\Rehashing;
use SineMacula\Laravel\Authentication\Sessions\WatchedSessions;
use SineMacula\Laravel\Authorization\Support\RequestState as AuthorizationRequestState;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Sso\Support\RequestState as SsoRequestState;

/**
 * Flushes the suite's request state between units of work in a long-lived
 * process.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final readonly class WorkerReset
{
    /** @var list<class-string> The scoped request state `laravel-authentication` has no public reset for. */
    private const array AUTHENTICATION_STATE = [
        Rehashing::class,
        KeptSessions::class,
        RequiredWork::class,
        WatchedSessions::class,
    ];

    /**
     * Constructor.
     *
     * @param  \Illuminate\Container\Container  $container
     */
    public function __construct(

        /** The application whose request state is flushed. */
        private Container $container,
    ) {}

    /**
     * Flush the guards, session, the suite's scoped instances and facade roots.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function reset(): void
    {
        $this->forgetMemberState();

        SsoRequestState::forget($this->container);
        AuthorizationRequestState::forget($this->container);

        foreach (self::AUTHENTICATION_STATE as $abstract) {
            $this->container->forgetInstance($abstract);
        }

        foreach (array_keys($this->container->getBindings()) as $abstract) {

            if (!str_starts_with($abstract, SeamBinding::SCOPED_PREFIX)) {
                continue;
            }

            $this->container->forgetInstance($abstract);
        }

        // A facade keeps its root outside the container.
        Facade::clearResolvedInstances();
    }

    /**
     * Flush the session and reset the resolved guards.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function forgetMemberState(): void
    {
        $this->flushSession();

        if (!$this->container->resolved('auth')) {
            return;
        }

        $auth = $this->container->make('auth');

        // Under Octane the shared manager may hold the last request's sandbox.
        if ($this->container instanceof Application) {
            $auth->setApplication($this->container);
        }

        $auth->forgetGuardState();
    }

    /**
     * Flush the resolved session, which holds laravel-mfa's default proofs.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function flushSession(): void
    {
        if (!$this->container->resolved(Session::class)) {
            return;
        }

        $this->container->make(Session::class)->flush();
    }
}
