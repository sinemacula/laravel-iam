<?php

declare(strict_types = 1);

namespace Tests\Unit\Workers;

use Illuminate\Auth\AuthManager as IlluminateAuthManager;
use Illuminate\Container\Container;
use Illuminate\Contracts\Container\Container as ContainerContract;
use Illuminate\Contracts\Session\Session;
use Illuminate\Log\Context\Repository as ContextRepository;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Defer\DeferredCallbackCollection;
use Illuminate\Support\Facades\Context;
use Illuminate\Support\Facades\Facade;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Database\RequiredWork;
use SineMacula\Laravel\Authentication\Sessions\KeptSessions;
use SineMacula\Laravel\Authentication\Sessions\Methods\Rehashing;
use SineMacula\Laravel\Authentication\Sessions\WatchedSessions;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Context\CheckContextFactory;
use SineMacula\Laravel\Authorization\Contracts\PolicyResolver;
use SineMacula\Laravel\Authorization\Contracts\PolicyStore;
use SineMacula\Laravel\Authorization\Contracts\RequestContext;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Evaluation\LastDecisionStore;
use SineMacula\Laravel\Authorization\Evaluation\PolicyEvaluator;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Support\DeclaredAbilities;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use SineMacula\Laravel\Authorization\Support\SessionScopes;
use SineMacula\Laravel\Iam\Bindings\BindingRule;
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
     * Clear the facades' resolved roots and the application they resolve from,
     * so no test's container reaches another.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Facade::clearResolvedInstances();
        Facade::setFacadeApplication(null);

        parent::tearDown();
    }

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
     * Rows of `[abstract]`: each scoped binding `laravel-authentication`,
     * `laravel-sso` and `laravel-authorization` keep request state in,
     * authorization's manager and the keys that hold its scoped defaults, each
     * found by their prefix, among them.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMembersScopedState(): iterable
    {
        $abstracts = [
            Rehashing::class,
            KeptSessions::class,
            RequiredWork::class,
            WatchedSessions::class,
            SingleUseStore::class,
            SecretEncrypter::class,
            Fetcher::class,
            AttemptLimiter::class,
            DnsResolver::class,
            Enforcement::class,
            EndpointResolver::class,
            HandoffIssuer::class,
            DriverScope::class,
            ResolvedTenant::class,
            ResolutionCache::class,
            LastDecisionStore::class,
            PolicyEvaluator::class,
            SessionScopes::class,
            CheckContextFactory::class,
            DeclaredAbilities::class,
            'authorization',
            'authorization.default:' . SubjectResolver::class,
            'authorization.default:' . PolicyStore::class,
            'authorization.default:' . PolicyResolver::class,
            'authorization.default:' . TenantTree::class,
            'authorization.default:' . RequestContext::class,
        ];

        foreach ($abstracts as $abstract) {
            yield $abstract => [$abstract];
        }
    }

    /**
     * The reset forgets each scoped instance a member keeps request state in,
     * so the next unit of work builds its own.
     *
     * @param  string  $abstract
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
     * The reset forgets each adapter this package scopes, under the key the
     * binding rule scopes it under, so the next unit of work builds its own.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testResetForgetsThePackagesScopedAdapters(): void
    {
        $container = new Container;
        $abstract  = BindingRule::SCOPED_PREFIX . SingleUseStore::class;

        $container->scoped($abstract, static fn (): \stdClass => new \stdClass);

        $before = $container->make($abstract);

        (new WorkerReset($container))->reset();

        self::assertNotSame($before, $container->make($abstract));
    }

    /**
     * Rows of `[abstract]`: scoped instances outside the members' request
     * state, Laravel's `Context` and deferred callbacks, the audit log's
     * execution frames and the application's own, one of them under a key that
     * only holds authorization's prefix further in.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideOtherScopedInstances(): iterable
    {
        $abstracts = [
            ContextRepository::class,
            DeferredCallbackCollection::class,
            ExecutionFrames::class,
            'application-scoped',
            'application.authorization.default:' . TenantTree::class,
        ];

        foreach ($abstracts as $abstract) {
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
     * Another scoped instance the container lists before a member's is kept,
     * and the member's is still forgotten, whatever order they were scoped in.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testResetForgetsTheMembersScopedStateListedAfterAnotherScopedInstance(): void
    {
        $container = new Container;

        $container->scoped(ContextRepository::class, static fn (): \stdClass => new \stdClass);
        $container->scoped(SingleUseStore::class, static fn (): \stdClass => new \stdClass);

        $context = $container->make(ContextRepository::class);
        $before  = $container->make(SingleUseStore::class);

        (new WorkerReset($container))->reset();

        self::assertSame($context, $container->make(ContextRepository::class));
        self::assertNotSame($before, $container->make(SingleUseStore::class));
    }

    /**
     * A scoped binding keyed by its closure's return type, which the container
     * lists as the closure itself, is kept, and a member's scoped instance
     * listed after it is still forgotten.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testResetKeepsAScopedBindingKeyedByItsClosure(): void
    {
        $container = new Container;

        $container->scoped(static fn (): \stdClass => new \stdClass);
        $container->scoped(SingleUseStore::class, static fn (): \stdClass => new \stdClass);

        $closureScoped = $container->make(\stdClass::class);
        $before        = $container->make(SingleUseStore::class);

        (new WorkerReset($container))->reset();

        self::assertSame($closureScoped, $container->make(\stdClass::class));
        self::assertNotSame($before, $container->make(SingleUseStore::class));
    }

    /**
     * The reset clears the root a facade resolved from a member's scoped
     * instance, so the facade resolves the next unit of work's own, as
     * `laravel-authorization`'s `Authorization` facade resolves its manager.
     *
     * @return void
     */
    public function testResetClearsTheRootAFacadeResolvedFromAMembersScopedState(): void
    {
        $container = new Container;

        $container->scoped('authorization', static fn (): \stdClass => new \stdClass);

        Facade::setFacadeApplication($container);

        $before = Authorization::getFacadeRoot();

        (new WorkerReset($container))->reset();

        self::assertNotSame($before, Authorization::getFacadeRoot());
        self::assertSame($container->make('authorization'), Authorization::getFacadeRoot());
    }

    /**
     * A facade over a scoped instance the reset keeps still returns that same
     * instance once its root is cleared, as Laravel's `Context` facade does.
     *
     * @return void
     */
    public function testAFacadeOverAKeptScopedInstanceReturnsTheSameInstance(): void
    {
        $container = new Container;

        $container->scoped(ContextRepository::class, static fn (): \stdClass => new \stdClass);

        Facade::setFacadeApplication($container);

        $before = Context::getFacadeRoot();

        (new WorkerReset($container))->reset();

        self::assertSame($before, Context::getFacadeRoot());
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
     * The reset keeps an instance the application bound over a member's scoped
     * seam with no scoped binding beneath it, as one bound before the member
     * registered, which the member's `scopedIf()` then left alone: it is the
     * application's, not request state, and nothing could rebuild it.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testResetKeepsAnInstanceWithNoScopedBinding(): void
    {
        $container = new Container;
        $instance  = new \stdClass;

        $container->instance(Fetcher::class, $instance);

        (new WorkerReset($container))->reset();

        self::assertSame($instance, self::resolve($container, Fetcher::class));
    }

    /**
     * The reset keeps a shared instance of a member's scoped seam the
     * application bound as a singleton of its own, so it is never rebuilt.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testResetKeepsASingletonOverAMembersScopedSeam(): void
    {
        $container = new Container;

        $container->singleton(Fetcher::class, static fn (): \stdClass => new \stdClass);

        $before = $container->make(Fetcher::class);

        (new WorkerReset($container))->reset();

        self::assertSame($before, $container->make(Fetcher::class));
    }

    /**
     * The reset flushes the session already resolved, where `laravel-mfa`'s
     * default proof store keeps its proofs, so the next unit of work reads none
     * of them, whether or not any guard is resolved.
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
     * Forgetting the members' state alone flushes the session too, beside the
     * guards.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testForgettingTheMemberStateFlushesTheSession(): void
    {
        $container = new Container;
        $session   = self::sessionHoldingProofs();

        $container->instance('auth', $this->managerForgettingOnce());
        $container->instance('session.store', $session);
        $container->alias('session.store', Session::class);

        (new WorkerReset($container))->forgetMemberState();

        self::assertSame([], $session->all());
    }

    /**
     * A session nothing has resolved holds nothing, so the reset does not build
     * one.
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
     * A `session.store` binding that is not a session is left alone, and the
     * rest of the reset still runs.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnotherSessionStoreIsLeftAlone(): void
    {
        $container = new Container;
        $store     = \Mockery::mock();
        $store->shouldNotReceive('flush');

        $container->instance('auth', $this->managerForgettingOnce());
        $container->instance('session.store', $store);
        $container->alias('session.store', Session::class);
        $container->scoped(DriverScope::class, static fn (): \stdClass => new \stdClass);

        $before = $container->make(DriverScope::class);

        (new WorkerReset($container))->reset();

        self::assertNotSame($before, $container->make(DriverScope::class));
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
        $container->shouldReceive('resolved')->with(Session::class)->andReturnFalse();
        $container->shouldReceive('make')->with('auth')->andReturn($this->managerForgettingOnce());

        (new WorkerReset($container))->reset();
    }

    /**
     * Resolve the abstract from the container, as whatever the container holds
     * for it, not as the member binds it.
     *
     * @param  \Illuminate\Container\Container  $container
     * @param  string  $abstract
     * @return mixed
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private static function resolve(Container $container, string $abstract): mixed
    {
        return $container->make($abstract);
    }

    /**
     * Return a session holding a proof record, as `laravel-mfa`'s default proof
     * store leaves one.
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
