<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Workers;

use Illuminate\Container\Container;
use Illuminate\Contracts\Session\Session;
use Illuminate\Support\Facades\Facade;

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
     * Flush the session, guards, scoped instances and facade roots.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function reset(): void
    {
        $this->flushSession();

        if ($this->container->resolved('auth')) {
            $this->container->make('auth')->forgetGuardState();
        }

        $this->container->forgetScopedInstances();

        // A facade keeps its root outside the container.
        Facade::clearResolvedInstances();
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
