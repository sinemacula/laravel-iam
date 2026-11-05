<?php

declare(strict_types = 1);

namespace Tests\Feature\Workers;

use Illuminate\Container\Container;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Event;
use Orchestra\Testbench\Attributes\DefineEnvironment;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Iam\Workers\ResetWhenWorkerStarts;
use SineMacula\Laravel\Sso\Protocols\DriverScope;
use Tests\Fixtures\Workers\WorkerStartingStandIn;
use Tests\TestCase;

/**
 * Feature tests for flushing every member's request state, the members' scoped
 * instances included, from the application an Octane worker clones its
 * requests' sandboxes from, as the worker starts, with Octane absent and its
 * event dispatched by name.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ResetWhenWorkerStarts::class)]
final class ResetWhenWorkerStartsTest extends TestCase
{
    /**
     * The listener is registered for Octane's event by its name, with Octane
     * not installed.
     *
     * @return void
     */
    public function testTheListenerIsRegisteredByTheEventsName(): void
    {
        self::assertFalse(class_exists(ResetWhenWorkerStarts::EVENT));
        self::assertContains(ResetWhenWorkerStarts::class, Event::getRawListeners()[ResetWhenWorkerStarts::EVENT] ?? []);
    }

    /**
     * The worker's start resets the guards and forgets the members' scoped
     * instances of the application the event carries, not of the current one.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheWorkersStartResetsTheEventsApplication(): void
    {
        $this->app?->instance('auth', $this->managerLeftAlone());

        $worker = new Container;

        $worker->instance('auth', $this->managerForgettingOnce());
        $worker->scoped(DriverScope::class);

        $before = $worker->make(DriverScope::class);

        Event::dispatch(ResetWhenWorkerStarts::EVENT, [new WorkerStartingStandIn($worker)]);

        self::assertNotSame($before, $worker->make(DriverScope::class));
    }

    /**
     * An event that carries no application resets the current one.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnEventWithoutAnApplicationResetsTheCurrentOne(): void
    {
        $before = $this->scopedInstanceOfTheApplication();

        Event::dispatch(ResetWhenWorkerStarts::EVENT, [new \stdClass]);

        self::assertNotSame($before, $this->app?->make(DriverScope::class));
    }

    /**
     * An application that is not a container is passed over for the current
     * one.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnApplicationThatIsNotAContainerResetsTheCurrentOne(): void
    {
        $before = $this->scopedInstanceOfTheApplication();

        Event::dispatch(ResetWhenWorkerStarts::EVENT, [new WorkerStartingStandIn('app')]);

        self::assertNotSame($before, $this->app?->make(DriverScope::class));
    }

    /**
     * With the reset turned off, no listener is registered.
     *
     * @return void
     */
    #[DefineEnvironment('turnTheResetOff')]
    public function testTurningTheResetOffRegistersNoListener(): void
    {
        $this->app?->instance('auth', $this->managerLeftAlone());

        Event::dispatch(ResetWhenWorkerStarts::EVENT, [new \stdClass]);

        self::assertArrayNotHasKey(ResetWhenWorkerStarts::EVENT, Event::getRawListeners());
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
     * Bind a `laravel-authentication` auth manager expecting its guard state
     * forgotten once, and return the application's instance of a member's
     * scoped seam.
     *
     * @return object
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function scopedInstanceOfTheApplication(): object
    {
        $this->app?->instance('auth', $this->managerForgettingOnce());
        $instance = $this->app?->make(DriverScope::class);

        self::assertIsObject($instance);

        return $instance;
    }

    /**
     * Return a `laravel-authentication` auth manager that expects its guard
     * state forgotten exactly once.
     *
     * @return \SineMacula\Laravel\Authentication\AuthManager
     */
    private function managerForgettingOnce(): AuthManager
    {
        $manager = \Mockery::mock(AuthManager::class);
        $manager->shouldReceive('forgetGuardState')->once();

        return $manager;
    }

    /**
     * Return a `laravel-authentication` auth manager that expects its guard
     * state left alone.
     *
     * @return \SineMacula\Laravel\Authentication\AuthManager
     */
    private function managerLeftAlone(): AuthManager
    {
        $manager = \Mockery::mock(AuthManager::class);
        $manager->shouldNotReceive('forgetGuardState');

        return $manager;
    }
}
