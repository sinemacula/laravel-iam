<?php

declare(strict_types = 1);

namespace Tests\Feature\Workers;

use Illuminate\Auth\AuthManager as IlluminateAuthManager;
use Illuminate\Container\Container;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Foundation\Application as FoundationApplication;
use Illuminate\Support\Facades\Event;
use Orchestra\Testbench\Attributes\DefineEnvironment;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Iam\Workers\ResetBetweenRequests;
use SineMacula\Laravel\Sso\Protocols\DriverScope;
use Tests\Concerns\ReadsRawListeners;
use Tests\Fixtures\Workers\RequestReceivedStandIn;
use Tests\TestCase;

/**
 * Feature tests for the reset before each Octane request, with Octane absent.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ResetBetweenRequests::class)]
final class ResetBetweenRequestsTest extends TestCase
{
    use ReadsRawListeners;

    /**
     * The listener is registered by the event's name without Octane installed.
     *
     * @return void
     */
    public function testTheListenerIsRegisteredByTheEventsName(): void
    {
        self::assertFalse(class_exists(ResetBetweenRequests::EVENT));
        self::assertContains(ResetBetweenRequests::class, self::rawListenersOf(ResetBetweenRequests::EVENT));
    }

    /**
     * Each request resets the event's sandbox, keeping its scoped instances.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEachRequestResetsTheEventsSandbox(): void
    {
        $this->app?->instance('auth', $this->managerLeftAlone());

        $sandbox = new Container;

        $sandbox->instance('auth', $this->managerForgettingOnce());
        $sandbox->scoped(DriverScope::class);

        $before = $sandbox->make(DriverScope::class);

        Event::dispatch(ResetBetweenRequests::EVENT, [new RequestReceivedStandIn($sandbox)]);

        self::assertSame($before, $sandbox->make(DriverScope::class));
    }

    /**
     * The guards reset against the request's sandbox, not the manager's last.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEachRequestResetsTheGuardsWhateverSandboxTheAuthManagerLastHeld(): void
    {
        $app  = $this->application();
        $auth = $app->make('auth');

        self::assertInstanceOf(AuthManager::class, $auth);

        $previous = clone $app;

        $auth->setApplication($previous);
        $previous->flush();

        $sandbox = clone $app;

        Event::dispatch(ResetBetweenRequests::EVENT, [new RequestReceivedStandIn($sandbox)]);

        self::assertSame($sandbox, \Closure::bind(fn (): mixed => $this->app, $auth, IlluminateAuthManager::class)());
    }

    /**
     * A scoped instance an earlier listener filled outlives the reset.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAScopedInstanceAnEarlierListenerFilledOutlivesTheReset(): void
    {
        $app = $this->app;

        self::assertNotNull($app);

        $app->instance('auth', $this->managerForgettingOnce($app));
        $app->scoped('request-trace', static fn (): \stdClass => new \stdClass);

        $trace  = null;
        $events = $app->make('events');

        $events->forget(ResetBetweenRequests::EVENT);
        $events->listen(ResetBetweenRequests::EVENT, static function () use ($app, &$trace): void {
            $trace = $app->make('request-trace');
        });
        $events->listen(ResetBetweenRequests::EVENT, ResetBetweenRequests::class);

        $events->dispatch(ResetBetweenRequests::EVENT, [new RequestReceivedStandIn($app)]);

        self::assertNotNull($trace);
        self::assertSame($trace, $app->make('request-trace'));
    }

    /**
     * An event that carries no sandbox resets the current application.
     *
     * @return void
     */
    public function testAnEventWithoutASandboxResetsTheCurrentApplication(): void
    {
        $this->app?->instance('auth', $this->managerForgettingOnce($this->application()));

        Event::dispatch(ResetBetweenRequests::EVENT, [new \stdClass]);
    }

    /**
     * A sandbox that is not a container falls back to the current application.
     *
     * @return void
     */
    public function testASandboxThatIsNotAContainerResetsTheCurrentApplication(): void
    {
        $this->app?->instance('auth', $this->managerForgettingOnce($this->application()));

        Event::dispatch(ResetBetweenRequests::EVENT, [new RequestReceivedStandIn('sandbox')]);
    }

    /**
     * With the reset off, no listener is registered.
     *
     * @return void
     */
    #[DefineEnvironment('turnTheResetOff')]
    public function testTurningTheResetOffRegistersNoListener(): void
    {
        $this->app?->instance('auth', $this->managerLeftAlone());

        Event::dispatch(ResetBetweenRequests::EVENT, [new \stdClass]);

        self::assertArrayNotHasKey(ResetBetweenRequests::EVENT, Event::getRawListeners());
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
     * Return the booted application.
     *
     * @return \Illuminate\Foundation\Application
     */
    private function application(): FoundationApplication
    {
        self::assertNotNull($this->app);

        return $this->app;
    }

    /**
     * An auth manager expecting its guard state forgotten exactly once.
     *
     * @param  \Illuminate\Contracts\Foundation\Application|null  $app
     * @return \SineMacula\Laravel\Authentication\AuthManager
     */
    private function managerForgettingOnce(?Application $app = null): AuthManager
    {
        $manager = \Mockery::mock(AuthManager::class);

        if ($app !== null) {
            $manager->shouldReceive('setApplication')->once()->with($app)->ordered()->andReturnSelf();
        }

        $manager->shouldReceive('forgetGuardState')->once()->ordered();

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
