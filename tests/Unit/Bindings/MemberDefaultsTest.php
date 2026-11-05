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
 * application's.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MemberDefaults::class)]
final class MemberDefaultsTest extends TestCase
{
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
}
