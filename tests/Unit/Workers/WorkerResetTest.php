<?php

declare(strict_types = 1);

namespace Tests\Unit\Workers;

use Illuminate\Auth\AuthManager as IlluminateAuthManager;
use Illuminate\Container\Container;
use Illuminate\Contracts\Container\Container as ContainerContract;
use Illuminate\Log\Context\Repository as ContextRepository;
use Illuminate\Support\Defer\DeferredCallbackCollection;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Sessions\Methods\Rehashing;
use SineMacula\Laravel\Iam\Workers\WorkerReset;
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
 * Unit tests for flushing every member's request state in a long-lived process.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(WorkerReset::class)]
final class WorkerResetTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * The reset sets every `laravel-authentication` guard already resolved back
     * to the current request.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testResetForgetsTheGuardState(): void
    {
        $container = new Container;

        $container->instance('auth', $this->managerForgettingOnce());

        (new WorkerReset($container))->reset();
    }

    /**
     * Rows of `[abstract]`: each scoped seam `laravel-authentication` and
     * `laravel-sso` keep request state in.
     *
     * @return iterable<string, array{0: class-string}>
     */
    public static function provideMembersScopedState(): iterable
    {
        $abstracts = [
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

        foreach ($abstracts as $abstract) {
            yield $abstract => [$abstract];
        }
    }

    /**
     * The reset forgets each scoped instance a member keeps request state in,
     * so the next unit of work builds its own.
     *
     * @param  class-string  $abstract
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideMembersScopedState')]
    public function testResetForgetsTheMembersScopedState(string $abstract): void
    {
        $container = new Container;

        $container->scoped($abstract, static fn (): \stdClass => new \stdClass);

        $before = $container->make($abstract);

        (new WorkerReset($container))->reset();

        self::assertNotSame($before, $container->make($abstract));
    }

    /**
     * Rows of `[abstract]`: scoped instances outside the members' request
     * state, Laravel's `Context` and deferred callbacks, the audit log's
     * execution frames and the application's own.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideOtherScopedInstances(): iterable
    {
        foreach ([ContextRepository::class, DeferredCallbackCollection::class, ExecutionFrames::class, 'application-scoped'] as $abstract) {
            yield $abstract => [$abstract];
        }
    }

    /**
     * The reset keeps every other scoped instance, so what the process queued
     * or entered for its own unit of work is still there after it.
     *
     * @param  string  $abstract
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideOtherScopedInstances')]
    public function testResetKeepsEveryOtherScopedInstance(string $abstract): void
    {
        $container = new Container;

        $container->scoped($abstract, static fn (): \stdClass => new \stdClass);

        $before = $container->make($abstract);

        (new WorkerReset($container))->reset();

        self::assertSame($before, $container->make($abstract));
    }

    /**
     * Forgetting the members' state alone resets the guards and keeps every
     * scoped instance.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testForgettingTheMemberStateKeepsTheScopedInstances(): void
    {
        $container = new Container;

        $container->instance('auth', $this->managerForgettingOnce());
        $container->scoped(DriverScope::class, static fn (): \stdClass => new \stdClass);

        $before = $container->make(DriverScope::class);

        (new WorkerReset($container))->forgetMemberState();

        self::assertSame($before, $container->make(DriverScope::class));
    }

    /**
     * An auth manager nothing has resolved holds no guard, so the reset does
     * not build one.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnUnresolvedAuthManagerIsNotBuilt(): void
    {
        $container = new Container;

        $container->singleton('auth', fn (): AuthManager => $this->managerForgettingOnce());

        (new WorkerReset($container))->reset();

        self::assertFalse($container->resolved('auth'));
    }

    /**
     * An `auth` binding that is not `laravel-authentication`'s manager is left
     * alone.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnotherAuthManagerIsLeftAlone(): void
    {
        $manager = \Mockery::mock(IlluminateAuthManager::class);
        $manager->shouldNotReceive('forgetGuardState');

        $container = new Container;

        $container->instance('auth', $manager);

        (new WorkerReset($container))->reset();
    }

    /**
     * A container that keeps no scoped instances still has its guards reset.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAContainerWithoutScopedInstancesStillHasItsGuardsReset(): void
    {
        $container = \Mockery::mock(ContainerContract::class);
        $container->shouldReceive('resolved')->with('auth')->andReturnTrue();
        $container->shouldReceive('make')->with('auth')->andReturn($this->managerForgettingOnce());

        (new WorkerReset($container))->reset();
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
}
