<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Container\Container;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Facade;

/**
 * Runs work in a sandbox of the application, made as Octane makes one for each
 * request: the worker's application cloned, the clone made the current
 * application (its own `app` and container, the container's global instance and
 * the facades' application, their resolved roots cleared), and its scoped
 * instances forgotten, so it holds the request's records alone. What the
 * worker's application resolved before the clone (a singleton, the events
 * dispatcher and the container it was built with) is shared with the sandbox,
 * as under Octane. The worker's application is made current again afterwards.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait RunsInOctaneSandboxes
{
    /**
     * Run the work in a sandbox of the application, and answer what it answers.
     *
     * @template T
     *
     * @param  \Closure(\Illuminate\Foundation\Application): T  $work
     * @return T
     */
    private function inOctaneSandbox(\Closure $work): mixed
    {
        $app = $this->app ?? self::fail('The application has not booted.');

        self::assertInstanceOf(Application::class, $app);

        $sandbox = clone $app;

        self::makeCurrent($sandbox);

        $sandbox->forgetScopedInstances();

        try {
            return $work($sandbox);
        } finally {
            self::makeCurrent($app);
        }
    }

    /**
     * Make the application the current one, as Octane's `CurrentApplication`
     * does.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    private static function makeCurrent(Application $app): void
    {
        $app->instance('app', $app);
        $app->instance(Container::class, $app);

        Container::setInstance($app);

        Facade::clearResolvedInstances();
        Facade::setFacadeApplication($app);
    }
}
