<?php

declare(strict_types = 1);

namespace Tests\Unit\Checks;

use Illuminate\Container\Container;
use Illuminate\Contracts\Container\Container as ContainerContract;
use Illuminate\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Bindings\BindingRule;
use SineMacula\Laravel\Iam\Bindings\Enums\Lifetime;
use SineMacula\Laravel\Iam\Bindings\MemberDefaults;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Iam\Checks\SeamHolders;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Revocation\RevocationScope;
use SineMacula\Laravel\Sso\SsoServiceProvider;
use Tests\Fixtures\Bindings\Adapter;
use Tests\Fixtures\Bindings\ApplicationImplementation;
use Tests\Fixtures\Bindings\Contracts\PlainSeam;
use Tests\Fixtures\Bindings\Contracts\SharedSeam;
use Tests\Fixtures\Bindings\MemberDefault;
use Tests\Fixtures\Checks\ExtensibleDefault;

/**
 * Unit tests for naming the class a seam's live binding answers with, without
 * building anything new.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SeamHolders::class)]
final class SeamHoldersTest extends TestCase
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
     * An unbound seam names nothing.
     *
     * @return void
     */
    public function testAnUnboundSeamNamesNothing(): void
    {
        self::assertNull($this->holders()->of($this->container, PlainSeam::class));
    }

    /**
     * A class-string binding names its class, followed through the container
     * where that class is bound in turn; one bound to itself names itself.
     *
     * @return void
     */
    public function testAClassStringBindingNamesItsClass(): void
    {
        $this->container->bind(PlainSeam::class, MemberDefault::class);

        self::assertSame(MemberDefault::class, $this->holders()->of($this->container, PlainSeam::class));

        $this->container->bind(MemberDefault::class, ApplicationImplementation::class);

        self::assertSame(ApplicationImplementation::class, $this->holders()->of($this->container, PlainSeam::class));

        $this->container->bind(Adapter::class);

        self::assertSame(Adapter::class, $this->holders()->of($this->container, Adapter::class));
    }

    /**
     * A closure a member's class declares, a member's closure default, names
     * that class.
     *
     * @return void
     */
    public function testAMembersClosureNamesItsDeclarer(): void
    {
        $this->container->bind(SharedSeam::class, self::declaredBy(static fn (): object => new ApplicationImplementation, SsoServiceProvider::class));

        self::assertSame(SsoServiceProvider::class, $this->holders()->of($this->container, SharedSeam::class));
        self::assertTrue(SeamHolders::isMembersOwn(SsoServiceProvider::class));
        self::assertFalse(SeamHolders::isMembersOwn(self::class));
    }

    /**
     * A closure of the application's own names nothing: what it returns cannot
     * be read without building it, and the class declaring it does not tell.
     *
     * @return void
     */
    public function testAnApplicationsClosureNamesNothing(): void
    {
        $this->container->bind(SharedSeam::class, static fn (): object => new ApplicationImplementation);

        self::assertNull($this->holders()->of($this->container, SharedSeam::class));
    }

    /**
     * A closure declared outside any class names nothing.
     *
     * @return void
     */
    public function testAClosureOfNoClassNamesNothing(): void
    {
        $closure = \Closure::bind(static fn (): object => new ApplicationImplementation, null, null);

        $this->container->bind(PlainSeam::class, $closure);

        self::assertNull($this->holders()->of($this->container, PlainSeam::class));
    }

    /**
     * An alias names what it points to.
     *
     * @return void
     */
    public function testAnAliasNamesWhatItPointsTo(): void
    {
        $this->container->bind(Adapter::class);
        $this->container->alias(Adapter::class, PlainSeam::class);

        self::assertSame(Adapter::class, $this->holders()->of($this->container, PlainSeam::class));
    }

    /**
     * An instance, or a shared binding already resolved, names the instance
     * held; a value held that is no object names its type.
     *
     * @return void
     */
    public function testAnInstanceNamesItsClass(): void
    {
        $this->container->instance(PlainSeam::class, new ApplicationImplementation);
        $this->container->singleton(SharedSeam::class, MemberDefault::class);
        $this->container->make(SharedSeam::class);
        $this->container->instance('seam.value', 'value');

        self::assertSame(ApplicationImplementation::class, $this->holders()->of($this->container, PlainSeam::class));
        self::assertSame(MemberDefault::class, $this->holders()->of($this->container, SharedSeam::class));
        self::assertSame('string', $this->holders()->of($this->container, 'seam.value'));
    }

    /**
     * An anonymous class extending nothing, bound as an instance or by its
     * class name, is the application's own, named by where it is declared,
     * though its debug name starts with the member's contract it implements.
     *
     * @return void
     */
    public function testAnAnonymousImplementationIsTheApplicationsOwn(): void
    {
        $line           = __LINE__ + 1;
        $implementation = new class implements SessionRevocation {
            /**
             * Revoke the sessions in the scope.
             *
             * @param  \SineMacula\Laravel\Sso\Revocation\RevocationScope  $scope
             * @return void
             */
            #[\Override]
            public function revoke(RevocationScope $scope): void {}
        };

        $name = 'class@anonymous (' . __FILE__ . ':' . $line . ')';

        $this->container->instance(SessionRevocation::class, $implementation);
        $this->container->bind(PlainSeam::class, $implementation::class);

        self::assertSame($name, $this->holders()->of($this->container, SessionRevocation::class));
        self::assertSame($name, $this->holders()->of($this->container, PlainSeam::class));
        self::assertFalse(SeamHolders::isMembersOwn($name));
    }

    /**
     * An anonymous subclass, bound as an instance or by its class name, is
     * named by the class it extends, whose behaviour it inherits.
     *
     * @return void
     */
    public function testAnAnonymousSubclassNamesTheClassItExtends(): void
    {
        $subclass = new class extends ExtensibleDefault {};

        $this->container->instance(PlainSeam::class, $subclass);
        $this->container->bind(SharedSeam::class, $subclass::class);

        self::assertSame(ExtensibleDefault::class, $this->holders()->of($this->container, PlainSeam::class));
        self::assertSame(ExtensibleDefault::class, $this->holders()->of($this->container, SharedSeam::class));
    }

    /**
     * This package's scoped adapter, resolved through a key of its own, names
     * the adapter.
     *
     * @return void
     */
    public function testAScopedAdapterNamesTheAdapter(): void
    {
        $app = new Application;

        (new \ReflectionMethod(BindingRule::class, 'bindScoped'))->invoke(null, $app, new SeamBinding(PlainSeam::class, Adapter::class, [MemberDefault::class], Lifetime::SCOPED));

        self::assertTrue($app->bound(BindingRule::SCOPED_PREFIX . PlainSeam::class));
        self::assertSame(Adapter::class, $this->holders()->of($app, PlainSeam::class));
    }

    /**
     * Bindings that lead back to each other end, naming nothing.
     *
     * @return void
     */
    public function testBindingsLeadingBackToEachOtherNameNothing(): void
    {
        $this->container->bind(PlainSeam::class, SharedSeam::class);
        $this->container->bind(SharedSeam::class, PlainSeam::class);

        self::assertNull($this->holders()->of($this->container, PlainSeam::class));
    }

    /**
     * A binding is followed through at most eight bindings, so a longer chain
     * names nothing.
     *
     * @return void
     */
    public function testAChainLongerThanTheLimitNamesNothing(): void
    {
        $this->chain($this->container, 8);

        self::assertSame('chain.8', $this->holders()->of($this->container, 'chain.0'));

        $this->chain($this->container, 9);

        self::assertNull($this->holders()->of($this->container, 'chain.0'));
    }

    /**
     * An alias counts as one of the bindings followed.
     *
     * @return void
     */
    public function testAnAliasCountsAsABindingFollowed(): void
    {
        $this->container->alias('chain.0', PlainSeam::class);
        $this->chain($this->container, 7);

        self::assertSame('chain.7', $this->holders()->of($this->container, PlainSeam::class));

        $this->chain($this->container, 8);

        self::assertNull($this->holders()->of($this->container, PlainSeam::class));
    }

    /**
     * An alias names what its target's binding names, without building it.
     *
     * @return void
     */
    public function testAnAliasNamesWhatItsTargetsBindingNames(): void
    {
        $this->container->bind(SharedSeam::class, ApplicationImplementation::class);
        $this->container->alias(SharedSeam::class, PlainSeam::class);

        self::assertSame(ApplicationImplementation::class, $this->holders()->of($this->container, PlainSeam::class));
    }

    /**
     * This package's scoped key counts as one of the bindings followed.
     *
     * @return void
     */
    public function testAScopedKeyCountsAsABindingFollowed(): void
    {
        $app = new Application;

        (new \ReflectionMethod(BindingRule::class, 'bindScoped'))->invoke(null, $app, new SeamBinding(PlainSeam::class, Adapter::class, [MemberDefault::class], Lifetime::SCOPED));

        $app->bind(Adapter::class, 'chain.0');
        $this->chain($app, 5);

        self::assertSame('chain.5', $this->holders()->of($app, PlainSeam::class));

        $this->chain($app, 6);

        self::assertNull($this->holders()->of($app, PlainSeam::class));
    }

    /**
     * A member's closure that happens to use a `$concrete` or a `$key` names
     * the class that declares it, never what those hold; the application's
     * names nothing.
     *
     * @return void
     */
    public function testAClosureUsingTheContainersNamesNamesItsDeclarer(): void
    {
        $concrete = Adapter::class;
        $key      = SharedSeam::class;

        $this->container->bind(SharedSeam::class, Adapter::class);
        $this->container->bind(PlainSeam::class, self::declaredBy(static fn (): object => new $concrete, SsoServiceProvider::class));

        self::assertSame(SsoServiceProvider::class, $this->holders()->of($this->container, PlainSeam::class));

        $this->container->bind(PlainSeam::class, self::declaredBy(static fn (Container $container): mixed => $container->make($key), SsoServiceProvider::class));

        self::assertSame(SsoServiceProvider::class, $this->holders()->of($this->container, PlainSeam::class));

        $this->container->bind(PlainSeam::class, static fn (): object => new $concrete);

        self::assertNull($this->holders()->of($this->container, PlainSeam::class));
    }

    /**
     * A container that keeps no binding table this can read names nothing.
     *
     * @return void
     */
    public function testAContainerWithoutATableNamesNothing(): void
    {
        $container = \Mockery::mock(ContainerContract::class);
        $container->shouldReceive('bound')->andReturnTrue();

        self::assertNull($this->holders()->of($container, PlainSeam::class));
    }

    /**
     * The closure given, declared by the class given, as a closure of that
     * class's own is.
     *
     * @param  \Closure(mixed): mixed  $closure
     * @param  class-string  $class
     * @return \Closure(mixed): mixed
     */
    private static function declaredBy(\Closure $closure, string $class): \Closure
    {
        $declared = \Closure::bind($closure, null, $class);

        assert($declared instanceof \Closure);

        return $declared;
    }

    /**
     * Bind a chain of the given number of bindings, `chain.0` to `chain.1` and
     * so on, the last naming an unbound `chain.{length}`.
     *
     * @param  \Illuminate\Container\Container  $container
     * @param  int  $length
     * @return void
     */
    private function chain(Container $container, int $length): void
    {
        foreach (range(0, $length - 1) as $link) {
            $container->bind('chain.' . $link, 'chain.' . ($link + 1));
        }
    }

    /**
     * The holders, as the checks resolve them.
     *
     * @return \SineMacula\Laravel\Iam\Checks\SeamHolders
     */
    private function holders(): SeamHolders
    {
        return new SeamHolders(new MemberDefaults);
    }
}
