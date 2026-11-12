<?php

declare(strict_types = 1);

namespace Tests\Unit\Workers;

use Illuminate\Container\Container;
use Illuminate\Contracts\Session\Session;
use Illuminate\Foundation\Application;
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
use SineMacula\Laravel\Authentication\Contracts\ApplicationAccess;
use SineMacula\Laravel\Authentication\Database\RequiredWork;
use SineMacula\Laravel\Authentication\Sessions\KeptSessions;
use SineMacula\Laravel\Authentication\Sessions\Methods\Rehashing;
use SineMacula\Laravel\Authentication\Sessions\WatchedSessions;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Context\CheckContextFactory;
use SineMacula\Laravel\Authorization\Contracts\ConsoleSubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\PolicyResolver;
use SineMacula\Laravel\Authorization\Contracts\PolicyStore;
use SineMacula\Laravel\Authorization\Contracts\RequestContext;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Evaluation\DecisionMemory;
use SineMacula\Laravel\Authorization\Evaluation\LastDecisionStore;
use SineMacula\Laravel\Authorization\Evaluation\PolicyEvaluator;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Preview\Previewing;
use SineMacula\Laravel\Authorization\Query\SchemaInspector;
use SineMacula\Laravel\Authorization\Support\DeclaredAbilities;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use SineMacula\Laravel\Authorization\Support\SessionScopes;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
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
     * Rows of `[abstract]`: each scoped binding holding member state.
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
            'sso.default:' . SingleUseStore::class,
            'sso.default:' . SecretEncrypter::class,
            'sso.default:' . Fetcher::class,
            'sso.default:' . AttemptLimiter::class,
            'sso.default:' . DnsResolver::class,
            'sso.default:' . Enforcement::class,
            'sso.default:' . EndpointResolver::class,
            'sso.default:' . HandoffIssuer::class,
            DriverScope::class,
            ResolvedTenant::class,
            ResolutionCache::class,
            LastDecisionStore::class,
            DecisionMemory::class,
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
            'authorization.default:' . ConsoleSubjectResolver::class,
            Previewing::class,
            SchemaInspector::class,
        ];

        foreach ($abstracts as $abstract) {
            yield $abstract => [$abstract];
        }
    }

    /**
     * The reset forgets each scoped instance a member keeps request state in.
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
     * Rows of `[seam]`: seams this package scopes its adapter over.
     *
     * @return iterable<string, array{0: class-string}>
     */
    public static function provideScopedSeams(): iterable
    {
        yield 'SSO\'s single-use store' => [SingleUseStore::class];

        yield 'authorization\'s subject resolver' => [SubjectResolver::class];

        yield 'authentication\'s application access' => [ApplicationAccess::class];
    }

    /**
     * The reset forgets each adapter this package scopes.
     *
     * @param  class-string  $seam
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideScopedSeams')]
    public function testResetForgetsThePackagesScopedAdapters(string $seam): void
    {
        $container = new Container;
        $abstract  = SeamBinding::SCOPED_PREFIX . $seam;

        $container->scoped($abstract, static fn (): \stdClass => new \stdClass);

        $before = $container->make($abstract);

        (new WorkerReset($container))->reset();

        self::assertNotSame($before, $container->make($abstract));
    }

    /**
     * Rows of `[abstract]`: scoped instances outside the suite's state.
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
     * The reset keeps every other scoped instance.
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
     * A facade over a kept scoped instance still returns that instance.
     *
     * @return void
     */
    public function testAFacadeOverAKeptScopedInstanceReturnsTheSameInstance(): void
    {
        $container = new Application;

        Facade::setFacadeApplication($container);

        $before = Context::getFacadeRoot();

        (new WorkerReset($container))->reset();

        self::assertSame($before, Context::getFacadeRoot());
    }

    /**
     * Forgetting the member state keeps every scoped instance.
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
     * Forgetting the member state flushes the session too.
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
