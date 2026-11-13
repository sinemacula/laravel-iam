<?php

declare(strict_types = 1);

namespace Tests\Feature\Workers;

use Illuminate\Container\Container;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Event;
use Orchestra\Testbench\Attributes\DefineEnvironment;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Iam\IamServiceProvider;
use SineMacula\Laravel\Iam\Workers\ResetWhenWorkerStarts;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Protocols\DriverScope;
use Tests\Concerns\PermutesProviderOrder;
use Tests\Concerns\ReadsRawListeners;
use Tests\Fixtures\Workers\WorkerStartingStandIn;
use Tests\TestCase;

/**
 * Feature tests for the reset as an Octane worker starts, with Octane absent.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ResetWhenWorkerStarts::class)]
final class ResetWhenWorkerStartsTest extends TestCase
{
    use PermutesProviderOrder, ReadsRawListeners;

    /**
     * The listener is registered by the event's name without Octane installed.
     *
     * @return void
     */
    public function testTheListenerIsRegisteredByTheEventsName(): void
    {
        self::assertFalse(class_exists(ResetWhenWorkerStarts::EVENT));
        self::assertContains(ResetWhenWorkerStarts::class, self::rawListenersOf(ResetWhenWorkerStarts::EVENT));
    }

    /**
     * The worker's start resets the application the event carries.
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
     * An application that is not a container falls back to the current one.
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
     * An instance the application bound over a scoped seam outlives the reset.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnInstanceTheApplicationBindsBeforeSsoRegistersOutlivesTheWorkersStart(): void
    {
        $fetcher = \Mockery::mock(Fetcher::class);

        $this->bootInOrder([...self::MEMBER_PROVIDERS, IamServiceProvider::class], before: [Fetcher::class => $fetcher]);

        Event::dispatch(ResetWhenWorkerStarts::EVENT, [new WorkerStartingStandIn($this->app)]);

        self::assertSame($fetcher, $this->resolve(Fetcher::class));
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
     * Resolve the abstract as the application holds it.
     *
     * @param  string  $abstract
     * @return mixed
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function resolve(string $abstract): mixed
    {
        return $this->app?->make($abstract);
    }

    /**
     * The application's instance of a member's scoped seam.
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
     * An auth manager expecting its guard state forgotten exactly once.
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
     * An auth manager expecting its guard state left alone.
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
