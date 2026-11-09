<?php

declare(strict_types = 1);

namespace Tests\Unit\Bindings;

use Illuminate\Container\Container;
use Illuminate\Contracts\Container\Container as ContainerContract;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Bindings\MemberDefaults;
use Tests\Fixtures\Bindings\Adapter;
use Tests\Fixtures\Bindings\ApplicationImplementation;
use Tests\Fixtures\Bindings\Contracts\PlainSeam;
use Tests\Fixtures\Bindings\Contracts\SharedSeam;
use Tests\Fixtures\Bindings\MemberDefault;

/**
 * Unit tests for telling a member's own default binding of a seam from the
 * application's, and for recording what binds the application's binding again.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MemberDefaults::class)]
final class MemberDefaultsTest extends TestCase
{
    /** @var string The key a member holds its default under, which its binding of the seam resolves. */
    private const string DEFAULT_KEY = 'member.default:seam';

    /** @var \Illuminate\Container\Container The container the seams are bound in. */
    private Container $container;

    /**
     * Start every test with an empty container.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->container = new Container;
    }

    /**
     * Close Mockery's expectations.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        \Mockery::close();

        parent::tearDown();
    }

    /**
     * An unbound seam may be bound over, whatever the defaults.
     *
     * @return void
     */
    public function testAnUnboundSeamIsReplaceable(): void
    {
        self::assertTrue((new MemberDefaults)->isReplaceable($this->container, PlainSeam::class, []));
    }

    /**
     * A seam bound to a member default by class name may be bound over.
     *
     * @return void
     */
    public function testASeamBoundToADefaultByClassNameIsReplaceable(): void
    {
        $this->container->bind(PlainSeam::class, MemberDefault::class);

        self::assertTrue((new MemberDefaults)->isReplaceable($this->container, PlainSeam::class, [Adapter::class, MemberDefault::class]));
    }

    /**
     * A seam bound as a singleton to a member default by class name may be
     * bound over.
     *
     * @return void
     */
    public function testASeamBoundAsASingletonToADefaultIsReplaceable(): void
    {
        $this->container->singletonIf(SharedSeam::class, MemberDefault::class);

        self::assertTrue((new MemberDefaults)->isReplaceable($this->container, SharedSeam::class, [MemberDefault::class]));
    }

    /**
     * A seam bound by class name to a class that is not a member default is the
     * application's, and is kept.
     *
     * @return void
     */
    public function testASeamBoundToAnotherClassIsKept(): void
    {
        $this->container->bind(PlainSeam::class, ApplicationImplementation::class);

        self::assertFalse((new MemberDefaults)->isReplaceable($this->container, PlainSeam::class, [MemberDefault::class]));
    }

    /**
     * A seam bound to itself, which the container builds directly, is kept
     * unless the seam itself is named as a default.
     *
     * @return void
     */
    public function testASeamBoundToItselfIsReplaceableOnlyWhenNamedAsADefault(): void
    {
        $this->container->bind(MemberDefault::class);

        self::assertFalse((new MemberDefaults)->isReplaceable($this->container, MemberDefault::class, [Adapter::class]));
        self::assertTrue((new MemberDefaults)->isReplaceable($this->container, MemberDefault::class, [MemberDefault::class]));
    }

    /**
     * A seam bound to a closure that a member default declares may be bound
     * over.
     *
     * @return void
     */
    public function testASeamBoundToAClosureADefaultDeclaresIsReplaceable(): void
    {
        $this->container->bind(PlainSeam::class, fn (): MemberDefault => new MemberDefault);

        self::assertTrue((new MemberDefaults)->isReplaceable($this->container, PlainSeam::class, [self::class]));
    }

    /**
     * A static closure keeps the class that declares it, so a seam bound to one
     * a member default declares may be bound over.
     *
     * @return void
     */
    public function testASeamBoundToAStaticClosureADefaultDeclaresIsReplaceable(): void
    {
        $this->container->bind(PlainSeam::class, static fn (): MemberDefault => new MemberDefault);

        self::assertTrue((new MemberDefaults)->isReplaceable($this->container, PlainSeam::class, [self::class]));
    }

    /**
     * A seam bound to a closure that no member default declares is the
     * application's, and is kept.
     *
     * @return void
     */
    public function testASeamBoundToAClosureAnotherClassDeclaresIsKept(): void
    {
        $this->container->bind(PlainSeam::class, static fn (): MemberDefault => new MemberDefault);

        self::assertFalse((new MemberDefaults)->isReplaceable($this->container, PlainSeam::class, [MemberDefault::class]));
    }

    /**
     * Only the closure the container builds around a class name is read for the
     * class it was given; another closure that captures a default's name is
     * still named by the class that declares it, and is kept.
     *
     * @return void
     */
    public function testAClosureCapturingADefaultsNameIsNamedByItsDeclarer(): void
    {
        $concrete = MemberDefault::class;

        $this->container->bind(PlainSeam::class, static fn (): object => new $concrete);

        self::assertFalse((new MemberDefaults)->isReplaceable($this->container, PlainSeam::class, [MemberDefault::class]));
    }

    /**
     * A seam bound to a closure that no class declares is kept.
     *
     * @return void
     */
    public function testASeamBoundToAClosureNoClassDeclaresIsKept(): void
    {
        $this->container->bind(PlainSeam::class, \Closure::fromCallable('strval'));

        self::assertFalse((new MemberDefaults)->isReplaceable($this->container, PlainSeam::class, [MemberDefault::class]));
    }

    /**
     * An instance is the application's, and is kept even when it is of a member
     * default's class.
     *
     * @return void
     */
    public function testAnInstanceIsKept(): void
    {
        $this->container->instance(PlainSeam::class, new MemberDefault);

        self::assertFalse((new MemberDefaults)->isReplaceable($this->container, PlainSeam::class, [MemberDefault::class]));
    }

    /**
     * An instance bound over a member default is the application's, and is
     * kept, though the default's binding stays beneath it.
     *
     * @return void
     */
    public function testAnInstanceOverAMemberDefaultIsKept(): void
    {
        $this->container->bind(PlainSeam::class, MemberDefault::class);
        $this->container->instance(PlainSeam::class, new ApplicationImplementation);

        self::assertFalse((new MemberDefaults)->isReplaceable($this->container, PlainSeam::class, [MemberDefault::class]));
    }

    /**
     * An instance bound over a shared member default is the application's, and
     * is kept.
     *
     * @return void
     */
    public function testAnInstanceOverASharedMemberDefaultIsKept(): void
    {
        $this->container->singleton(SharedSeam::class, MemberDefault::class);
        $this->container->instance(SharedSeam::class, new ApplicationImplementation);

        self::assertFalse((new MemberDefaults)->isReplaceable($this->container, SharedSeam::class, [MemberDefault::class]));
    }

    /**
     * A shared member default that has already been resolved is kept, since
     * whatever resolved it holds that instance.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAResolvedSharedMemberDefaultIsKept(): void
    {
        $this->container->singleton(SharedSeam::class, MemberDefault::class);
        $this->container->make(SharedSeam::class);

        self::assertFalse((new MemberDefaults)->isReplaceable($this->container, SharedSeam::class, [MemberDefault::class]));
    }

    /**
     * A transient member default that has already been resolved holds no
     * instance, so it may still be bound over.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAResolvedTransientMemberDefaultIsReplaceable(): void
    {
        $this->container->bind(PlainSeam::class, MemberDefault::class);
        $this->container->make(PlainSeam::class);

        self::assertTrue((new MemberDefaults)->isReplaceable($this->container, PlainSeam::class, [MemberDefault::class]));
    }

    /**
     * A seam that is an alias of another binding is the application's, and is
     * kept even when it aliases a member default.
     *
     * @return void
     */
    public function testAnAliasIsKept(): void
    {
        $this->container->bind(MemberDefault::class);
        $this->container->alias(MemberDefault::class, PlainSeam::class);

        self::assertFalse((new MemberDefaults)->isReplaceable($this->container, PlainSeam::class, [MemberDefault::class]));
    }

    /**
     * An alias the application makes over a seam the member has already bound
     * is kept, though the member's default stays beneath it in the binding
     * table.
     *
     * @return void
     */
    public function testAnAliasOverAMemberDefaultIsKept(): void
    {
        $this->container->bind(PlainSeam::class, MemberDefault::class);
        $this->container->singleton(ApplicationImplementation::class);
        $this->container->alias(ApplicationImplementation::class, PlainSeam::class);

        self::assertFalse((new MemberDefaults)->isReplaceable($this->container, PlainSeam::class, [MemberDefault::class]));
    }

    /**
     * A bound seam in a container whose binding table cannot be read is kept,
     * since nothing shows it is a member default.
     *
     * @return void
     */
    public function testABoundSeamInAnotherContainerIsKept(): void
    {
        $container = \Mockery::mock(ContainerContract::class);

        $container->shouldReceive('bound')->with(PlainSeam::class)->andReturnTrue();

        self::assertFalse((new MemberDefaults)->isReplaceable($container, PlainSeam::class, [MemberDefault::class]));
    }

    /**
     * An unbound seam in a container whose binding table cannot be read may be
     * bound over.
     *
     * @return void
     */
    public function testAnUnboundSeamInAnotherContainerIsReplaceable(): void
    {
        $container = \Mockery::mock(ContainerContract::class);

        $container->shouldReceive('bound')->with(PlainSeam::class)->andReturnFalse();

        self::assertTrue((new MemberDefaults)->isReplaceable($container, PlainSeam::class, []));
    }

    /**
     * A seam the member binds to a closure resolving a key of its own is the
     * member's while the key holds the member's default class, and may be bound
     * over.
     *
     * @return void
     */
    public function testASeamResolvingAKeyThatHoldsTheDefaultIsReplaceable(): void
    {
        $this->bindThroughKey(MemberDefault::class);

        self::assertTrue((new MemberDefaults)->isReplaceable($this->container, PlainSeam::class, [self::class, MemberDefault::class], self::DEFAULT_KEY));
        self::assertTrue((new MemberDefaults)->holdsDefault($this->container, PlainSeam::class, [self::class, MemberDefault::class], self::DEFAULT_KEY));
    }

    /**
     * A seam the member binds to a closure resolving a key of its own that
     * holds another class, one the application named in the member's
     * configuration, is the application's, and is kept, though the member's
     * closure binds it.
     *
     * @return void
     */
    public function testASeamResolvingAKeyThatHoldsAnotherClassIsKept(): void
    {
        $this->bindThroughKey(ApplicationImplementation::class);

        self::assertFalse((new MemberDefaults)->isReplaceable($this->container, PlainSeam::class, [self::class, MemberDefault::class], self::DEFAULT_KEY));
        self::assertFalse((new MemberDefaults)->holdsDefault($this->container, PlainSeam::class, [self::class, MemberDefault::class], self::DEFAULT_KEY));
    }

    /**
     * A seam bound to anything but the member's closure is kept, whatever its
     * key holds.
     *
     * @return void
     */
    public function testASeamNotBoundThroughItsKeyIsKept(): void
    {
        $this->bindThroughKey(MemberDefault::class);
        $this->container->bind(PlainSeam::class, ApplicationImplementation::class);

        self::assertFalse((new MemberDefaults)->isReplaceable($this->container, PlainSeam::class, [self::class, MemberDefault::class], self::DEFAULT_KEY));
    }

    /**
     * An unbound seam may be bound over, but holds no member default.
     *
     * @return void
     */
    public function testAnUnboundSeamHoldsNoDefault(): void
    {
        self::assertTrue((new MemberDefaults)->isReplaceable($this->container, PlainSeam::class, [MemberDefault::class], self::DEFAULT_KEY));
        self::assertFalse((new MemberDefaults)->holdsDefault($this->container, PlainSeam::class, [MemberDefault::class], self::DEFAULT_KEY));
    }

    /**
     * A seam bound to the member's default class by its name may be bound over,
     * but holds no binding of the member's own: a member that binds through a
     * closure never binds it so.
     *
     * @return void
     */
    public function testADefaultClassBoundByNameIsNoMembersOwnBinding(): void
    {
        $this->container->bind(PlainSeam::class, MemberDefault::class);

        self::assertTrue((new MemberDefaults)->isReplaceable($this->container, PlainSeam::class, [MemberDefault::class]));
        self::assertFalse((new MemberDefaults)->holdsDefault($this->container, PlainSeam::class, [MemberDefault::class]));
    }

    /**
     * A seam bound to a closure no member default declares, or one no class
     * declares, holds no binding of the member's own.
     *
     * @return void
     */
    public function testAClosureNoMemberDefaultDeclaresIsNoMembersOwnBinding(): void
    {
        $this->container->bind(PlainSeam::class, static fn (): MemberDefault => new MemberDefault);
        $this->container->bind(SharedSeam::class, \Closure::fromCallable('strval'));

        self::assertFalse((new MemberDefaults)->holdsDefault($this->container, PlainSeam::class, [MemberDefault::class]));
        self::assertFalse((new MemberDefaults)->holdsDefault($this->container, SharedSeam::class, [MemberDefault::class]));
        self::assertTrue((new MemberDefaults)->holdsDefault($this->container, PlainSeam::class, [self::class]));
    }

    /**
     * A key holding an instance of exactly the default's class, resolved under
     * the member's scoped binding of it, still holds the default, so the seam
     * resolving it is the member's, while the same binding unresolved, which no
     * default declares, is not built to be judged; an instance of another class
     * there is the application's.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAKeyHoldingAResolvedInstanceIsJudgedByItsClass(): void
    {
        $defaults = [self::class, MemberDefault::class];

        $this->container->scoped(self::DEFAULT_KEY, self::declaredByNoClass());
        $this->container->bind(PlainSeam::class, static fn (Container $container): mixed => $container->make(self::DEFAULT_KEY));

        self::assertFalse((new MemberDefaults)->holdsDefault($this->container, PlainSeam::class, $defaults, self::DEFAULT_KEY));

        $this->container->make(PlainSeam::class);

        self::assertTrue((new MemberDefaults)->holdsDefault($this->container, PlainSeam::class, $defaults, self::DEFAULT_KEY));
        self::assertTrue((new MemberDefaults)->isReplaceable($this->container, PlainSeam::class, $defaults, self::DEFAULT_KEY));

        $this->container->forgetInstance(self::DEFAULT_KEY);
        $this->container->instance(self::DEFAULT_KEY, new ApplicationImplementation);

        self::assertFalse((new MemberDefaults)->holdsDefault($this->container, PlainSeam::class, $defaults, self::DEFAULT_KEY));
    }

    /**
     * A key resolved through a transient binding holds no instance, so nothing
     * is built to judge it, and a binding no default declares is kept, though
     * it builds the default's class.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAKeyResolvedTransientlyIsNotBuiltToBeJudged(): void
    {
        $this->container->bind(self::DEFAULT_KEY, self::declaredByNoClass());
        $this->container->bind(PlainSeam::class, static fn (Container $container): mixed => $container->make(self::DEFAULT_KEY));
        $this->container->make(PlainSeam::class);

        self::assertFalse((new MemberDefaults)->holdsDefault($this->container, PlainSeam::class, [self::class, MemberDefault::class], self::DEFAULT_KEY));
    }

    /**
     * What binds a seam again rebinds it exactly as it was: an alias, an
     * instance, a shared or a transient binding, each over whatever was bound
     * over it since; nothing for an unbound seam or a container that keeps no
     * binding table.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testWhatBindsASeamAgainRebindsItAsItWas(): void
    {
        $defaults = new MemberDefaults;

        self::assertNull($defaults->restorerOf($this->container, PlainSeam::class));
        self::assertNull($defaults->restorerOf(\Mockery::mock(ContainerContract::class), PlainSeam::class));

        $this->container->bind(ApplicationImplementation::class, ApplicationImplementation::class);
        $this->container->alias(ApplicationImplementation::class, PlainSeam::class);
        $this->assertRestored($defaults, static fn (Container $container, object $restored): bool => $restored instanceof ApplicationImplementation
            && $container->isAlias(PlainSeam::class));

        $instance = new ApplicationImplementation;

        $this->container->instance(PlainSeam::class, $instance);
        $this->assertRestored($defaults, static fn (Container $container, object $restored): bool => $restored === $instance);

        $this->container->singleton(PlainSeam::class, ApplicationImplementation::class);
        $this->assertRestored($defaults, static fn (Container $container, object $restored): bool => $restored instanceof ApplicationImplementation
            && $container->isShared(PlainSeam::class));

        $this->container->bind(PlainSeam::class, ApplicationImplementation::class);
        $this->assertRestored($defaults, static fn (Container $container, object $restored): bool => $restored instanceof ApplicationImplementation
            && !$container->isShared(PlainSeam::class));
    }

    /**
     * Record what binds the seam again, bind the member's default over it as a
     * member that binds unconditionally does, bind it again, and assert what it
     * resolves to.
     *
     * @param  \SineMacula\Laravel\Iam\Bindings\MemberDefaults  $defaults
     * @param  \Closure(\Illuminate\Container\Container, object): bool  $isRestored
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function assertRestored(MemberDefaults $defaults, \Closure $isRestored): void
    {
        $restorer = $defaults->restorerOf($this->container, PlainSeam::class);

        self::assertNotNull($restorer);

        $this->container->bind(PlainSeam::class, MemberDefault::class);

        self::assertInstanceOf(MemberDefault::class, $this->container->make(PlainSeam::class));

        $restorer($this->container);

        $restored = $this->container->make(PlainSeam::class);

        self::assertIsObject($restored);
        self::assertTrue($isRestored($this->container, $restored));

        $this->container->forgetInstance(PlainSeam::class);
    }

    /**
     * A closure building the member's default that no class declares, so its
     * binding names no default.
     *
     * @return \Closure(): \Tests\Fixtures\Bindings\MemberDefault
     */
    private static function declaredByNoClass(): \Closure
    {
        return \Closure::bind(static fn (): MemberDefault => new MemberDefault, null, null);
    }

    /**
     * Bind the seam as a member that binds its defaults unconditionally does:
     * the class given scoped under the member's own key, and the seam to a
     * closure this test declares resolving that key.
     *
     * @param  class-string  $concrete
     * @return void
     */
    private function bindThroughKey(string $concrete): void
    {
        $this->container->scoped(self::DEFAULT_KEY, $concrete);
        $this->container->bind(PlainSeam::class, static fn (Container $container): mixed => $container->make(self::DEFAULT_KEY));
    }
}
