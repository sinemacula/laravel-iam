<?php

declare(strict_types = 1);

namespace Tests\Feature\Bindings;

use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver;
use SineMacula\Laravel\Iam\Bindings\Enums\Lifetime;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Mfa\Contracts\TenantRequirement;
use SineMacula\Laravel\Sso\Contracts\TenantMembership;
use Tests\TestCase;

/**
 * Feature tests for binding an adapter over a member's seam.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SeamBinding::class)]
final class SeamBindingTest extends TestCase
{
    /**
     * A seam of each member still on that member's default.
     *
     * @return iterable<string, array{0: class-string}>
     */
    public static function provideMemberDefaults(): iterable
    {
        yield 'laravel-authentication' => [TenantResolver::class];

        yield 'laravel-authorization' => [ResourceTenantResolver::class];

        yield 'laravel-mfa' => [TenantRequirement::class];

        yield 'laravel-sso' => [TenantMembership::class];

        yield 'laravel-audit-log' => [Clock::class];
    }

    /**
     * Each member is asked about its own seam, and its default is replaced.
     *
     * @param  class-string  $abstract
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideMemberDefaults')]
    public function testTheAdapterReplacesAMembersDefault(string $abstract): void
    {
        $binding = new SeamBinding($abstract, \ArrayObject::class);

        self::assertTrue($binding->holdsDefault($this->container()));

        $binding->apply($this->container());

        self::assertInstanceOf(\ArrayObject::class, $this->resolve($abstract));
        self::assertFalse($binding->holdsDefault($this->container()));
    }

    /**
     * An unbound seam is bound.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnUnboundSeamIsBound(): void
    {
        $this->container()->offsetUnset(TenantResolver::class);

        (new SeamBinding(TenantResolver::class, \ArrayObject::class))->apply($this->container());

        self::assertInstanceOf(\ArrayObject::class, $this->resolve(TenantResolver::class));
    }

    /**
     * The application's own binding is kept.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheApplicationsBindingIsKept(): void
    {
        $own = new \ArrayObject;

        $this->container()->bind(TenantResolver::class, static fn (): \ArrayObject => $own);

        $binding = new SeamBinding(TenantResolver::class, \ArrayObject::class);

        $binding->apply($this->container());

        self::assertFalse($binding->holdsDefault($this->container()));
        self::assertSame($own, $this->resolve(TenantResolver::class));
    }

    /**
     * A binding switched off binds nothing.
     *
     * @return void
     */
    public function testABindingSwitchedOffBindsNothing(): void
    {
        $this->container()->offsetUnset(TenantResolver::class);

        (new SeamBinding(TenantResolver::class, \ArrayObject::class, false))->apply($this->container());

        self::assertFalse($this->container()->bound(TenantResolver::class));
    }

    /**
     * A transient adapter is built for each resolution, a shared one once.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTransientAndSharedAdaptersAreBuiltAsDeclared(): void
    {
        $container = $this->container();

        (new SeamBinding(TenantResolver::class, \ArrayObject::class))->apply($container);
        (new SeamBinding(Clock::class, \ArrayObject::class, lifetime: Lifetime::SHARED))->apply($container);

        self::assertNotSame($container->make(TenantResolver::class), $container->make(TenantResolver::class));
        self::assertSame($container->make(Clock::class), $container->make(Clock::class));
    }

    /**
     * A scoped adapter is held under this package's own scoped key.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAScopedAdapterIsHeldUnderItsOwnKey(): void
    {
        $container = $this->container();

        (new SeamBinding(TenantResolver::class, \ArrayObject::class, lifetime: Lifetime::SCOPED))->apply($container);

        $first = $container->make(TenantResolver::class);

        self::assertSame($first, $container->make(TenantResolver::class));
        self::assertSame($first, $container->make(SeamBinding::SCOPED_PREFIX . TenantResolver::class));
        self::assertFalse($container->isShared(TenantResolver::class));

        $container->forgetScopedInstances();

        self::assertNotSame($first, $container->make(TenantResolver::class));
    }

    /**
     * The bound adapter is declared; a kept application binding is not.
     *
     * @return void
     */
    public function testTheBoundAdapterIsDeclaredAndAKeptBindingIsNot(): void
    {
        $container = $this->container();
        $declared  = [];
        $declare   = static function (Container $container, \Closure $bound) use (&$declared): void {
            $declared[] = $bound;
        };

        (new SeamBinding(TenantResolver::class, \ArrayObject::class, declare: $declare))->apply($container);

        self::assertCount(1, $declared);
        self::assertSame($container->getBindings()[TenantResolver::class]['concrete'], $declared[0]);

        (new SeamBinding(TenantResolver::class, \ArrayObject::class, declare: $declare))->apply($container);

        self::assertCount(1, $declared);
    }

    /**
     * A binding is transient, on and optional unless declared otherwise.
     *
     * @return void
     */
    public function testABindingIsTransientOnAndOptionalByDefault(): void
    {
        $binding = new SeamBinding(TenantResolver::class, \ArrayObject::class);

        self::assertTrue($binding->on);
        self::assertSame(Lifetime::TRANSIENT, $binding->lifetime);
        self::assertFalse($binding->isMandatory());
        self::assertNull($binding->declare);
    }

    /**
     * A closure mandate is asked each time it is read, and never before.
     *
     * @return void
     */
    public function testAMandateDeclaredAsAClosureIsAskedWhenItIsRead(): void
    {
        $answers = [true, false];
        $asked   = new \ArrayObject;
        $binding = new SeamBinding(TenantResolver::class, \ArrayObject::class, mandatory: static function () use ($answers, $asked): bool {

            $asked->append(true);

            return $answers[count($asked) - 1];
        });

        self::assertCount(0, $asked);
        self::assertTrue($binding->isMandatory());
        self::assertFalse($binding->isMandatory());
        self::assertTrue((new SeamBinding(TenantResolver::class, \ArrayObject::class, mandatory: true))->isMandatory());
    }

    /**
     * A seam no member owns is refused.
     *
     * @return void
     */
    public function testASeamNoMemberOwnsIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(\ArrayObject::class . ' is no member\'s contract.');

        (new SeamBinding(\ArrayObject::class, \ArrayObject::class))->holdsDefault($this->container());
    }

    /**
     * Resolve the seam from the application's container.
     *
     * @param  string  $abstract
     * @return mixed
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function resolve(string $abstract): mixed
    {
        return $this->container()->make($abstract);
    }

    /**
     * The application's container.
     *
     * @return \Illuminate\Container\Container
     */
    private function container(): Container
    {
        $app = $this->app;

        self::assertNotNull($app);

        return $app;
    }
}
