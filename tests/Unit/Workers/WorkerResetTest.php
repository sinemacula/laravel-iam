<?php

declare(strict_types = 1);

namespace Tests\Unit\Workers;

use Illuminate\Container\Container;
use Illuminate\Contracts\Session\Session;
use Illuminate\Foundation\Application;
use Illuminate\Log\Context\Repository as ContextRepository;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Facade;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Sessions\KeptSessions;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Iam\Workers\WorkerReset;

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
     * Clear the facade roots and the global container.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Facade::clearResolvedInstances();
        Facade::setFacadeApplication(null);
        Container::setInstance();

        parent::tearDown();
    }

    /**
     * The reset forgets every resolved guard's state.
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
     * Rows of `[abstract]`: scoped state of a member, the package and Laravel.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideScopedInstances(): iterable
    {
        yield 'authentication\'s kept sessions' => [KeptSessions::class];

        yield 'this package\'s scoped adapter' => [SeamBinding::SCOPED_PREFIX . SubjectResolver::class];

        yield 'Laravel\'s context' => [ContextRepository::class];
    }

    /**
     * The reset forgets every scoped instance.
     *
     * @param  string  $abstract
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideScopedInstances')]
    public function testResetForgetsEveryScopedInstance(string $abstract): void
    {
        $container = new Container;

        $container->scoped($abstract, static fn (): \stdClass => new \stdClass);

        $before = $container->make($abstract);

        (new WorkerReset($container))->reset();

        self::assertNotSame($before, $container->make($abstract));
    }

    /**
     * The reset clears a facade root resolved from a member's scoped instance.
     *
     * @return void
     */
    public function testResetClearsTheRootAFacadeResolvedFromAMembersScopedState(): void
    {
        $container = new Application;

        $container->scoped('authorization', static fn (): \stdClass => new \stdClass);

        Facade::setFacadeApplication($container);

        $before = Authorization::getFacadeRoot();

        (new WorkerReset($container))->reset();

        self::assertNotSame($before, Authorization::getFacadeRoot());
        self::assertSame($container->make('authorization'), Authorization::getFacadeRoot());
    }

    /**
     * The reset flushes the resolved session.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testResetFlushesTheSession(): void
    {
        $container = new Container;
        $session   = self::sessionHoldingProofs();

        $container->instance('session.store', $session);
        $container->alias('session.store', Session::class);

        (new WorkerReset($container))->reset();

        self::assertSame([], $session->all());
    }

    /**
     * Flushing the session alone leaves the guards to `laravel-authentication`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testFlushingTheSessionLeavesTheGuardsAlone(): void
    {
        $container = new Container;
        $session   = self::sessionHoldingProofs();
        $manager   = \Mockery::mock(AuthManager::class);
        $manager->shouldNotReceive('forgetGuardState');

        $container->instance('auth', $manager);
        $container->instance('session.store', $session);
        $container->alias('session.store', Session::class);

        (new WorkerReset($container))->flushSession();

        self::assertSame([], $session->all());
    }

    /**
     * An unresolved session is not built.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnUnresolvedSessionIsNotBuilt(): void
    {
        $container = new Container;

        $container->singleton('session.store', static fn (): Store => self::sessionHoldingProofs());
        $container->alias('session.store', Session::class);

        (new WorkerReset($container))->reset();

        self::assertFalse($container->resolved('session.store'));
    }

    /**
     * An unresolved auth manager is not built.
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
     * A session holding a laravel-mfa proof record.
     *
     * @return \Illuminate\Session\Store
     */
    private static function sessionHoldingProofs(): Store
    {
        $session = new Store('worker', new ArraySessionHandler(120));

        $session->put('mfa-proofs', ['proof']);

        return $session;
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
}
