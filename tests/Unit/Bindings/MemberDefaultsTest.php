<?php

declare(strict_types = 1);

namespace Tests\Unit\Bindings;

use Illuminate\Container\Container;
use Illuminate\Contracts\Container\Container as ContainerContract;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\AuditLogServiceProvider;
use SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Iam\Bindings\MemberDefaults;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\MfaServiceProvider;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\SsoServiceProvider;
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
     * An unbound seam may be bound over, whatever the member says.
     *
     * @return void
     */
    public function testAnUnboundSeamIsReplaceable(): void
    {
        self::assertTrue((new MemberDefaults)->isReplaceable($this->container, PlainSeam::class, static fn (): bool => false));
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
        $this->container->singleton(SharedSeam::class, MemberDefault::build(...));
        $this->container->make(SharedSeam::class);

        self::assertFalse((new MemberDefaults)->isReplaceable($this->container, SharedSeam::class, MemberDefault::isPackageDefault(...)));
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
        $this->container->bind(PlainSeam::class, MemberDefault::build(...));
        $this->container->make(PlainSeam::class);

        self::assertTrue((new MemberDefaults)->isReplaceable($this->container, PlainSeam::class, MemberDefault::isPackageDefault(...)));
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

        self::assertTrue((new MemberDefaults)->isReplaceable($container, PlainSeam::class, static fn (): bool => false));
    }

    /**
     * The member is asked whether the seam holds its default, with the
     * container and the seam: the seam may be bound over, and holds the
     * default, exactly while the member says so.
     *
     * @return void
     */
    public function testAMemberThatAnswersIsAskedWhetherTheSeamHoldsItsDefault(): void
    {
        $asked = [];
        $says  = static function (bool $answer) use (&$asked): \Closure {
            return static function (Container $container, string $abstract) use (&$asked, $answer): bool {
                $asked[] = [$container, $abstract];

                return $answer;
            };
        };

        $this->container->bind(PlainSeam::class, static fn (): MemberDefault => new MemberDefault);
        $this->container->bind(SharedSeam::class, MemberDefault::class);

        self::assertTrue((new MemberDefaults)->isReplaceable($this->container, PlainSeam::class, $says(true)));
        self::assertTrue((new MemberDefaults)->holdsDefault($this->container, PlainSeam::class, $says(true)));
        self::assertFalse((new MemberDefaults)->isReplaceable($this->container, PlainSeam::class, $says(false)));
        self::assertFalse((new MemberDefaults)->holdsDefault($this->container, PlainSeam::class, $says(false)));
        self::assertFalse((new MemberDefaults)->isReplaceable($this->container, SharedSeam::class, $says(false)));
        self::assertSame([$this->container, PlainSeam::class], $asked[0]);
        self::assertCount(5, $asked);
    }

    /**
     * The member is never asked about a seam with no binding to read: an
     * unbound seam may be bound over but holds no default, and an instance or
     * an alias held over the member's binding is kept, as is a seam in a
     * container whose binding table cannot be read.
     *
     * @return void
     */
    public function testAMemberThatAnswersIsNotAskedWithNoBindingToRead(): void
    {
        $asked = 0;
        $says  = static function () use (&$asked): bool {
            $asked++;

            return true;
        };

        $this->container->bind(PlainSeam::class, static fn (): MemberDefault => new MemberDefault);
        $this->container->instance(PlainSeam::class, new MemberDefault);
        $this->container->bind(SharedSeam::class, static fn (): MemberDefault => new MemberDefault);
        $this->container->alias(PlainSeam::class, SharedSeam::class);

        $other = \Mockery::mock(ContainerContract::class);

        $other->shouldReceive('bound')->with(PlainSeam::class)->andReturnTrue();

        self::assertTrue((new MemberDefaults)->isReplaceable(new Container, PlainSeam::class, $says));
        self::assertFalse((new MemberDefaults)->holdsDefault(new Container, PlainSeam::class, $says));
        self::assertFalse((new MemberDefaults)->isReplaceable($this->container, PlainSeam::class, $says));
        self::assertFalse((new MemberDefaults)->isReplaceable($this->container, SharedSeam::class, $says));
        self::assertFalse((new MemberDefaults)->isReplaceable($other, PlainSeam::class, $says));
        self::assertFalse((new MemberDefaults)->holdsDefault($other, PlainSeam::class, $says));
        self::assertSame(0, $asked);
    }

    /**
     * Each member is asked whether a seam holds its default for its own
     * contracts, and a contract of no member's is refused.
     *
     * @return void
     *
     * @throws \ReflectionException
     */
    public function testEachContractIsAnsweredByItsOwnMember(): void
    {
        $members = [
            TenantResolver::class    => AuthenticationServiceProvider::class,
            TenantTree::class        => AuthorizationServiceProvider::class,
            ProofStore::class        => MfaServiceProvider::class,
            AuditAccessPolicy::class => AuditLogServiceProvider::class,
            Linker::class            => SsoServiceProvider::class,
        ];

        foreach ($members as $contract => $provider) {
            $answer = new \ReflectionFunction(MemberDefaults::answerOf($contract));

            self::assertSame('isPackageDefault', $answer->getName());
            self::assertSame($provider, $answer->getClosureScopeClass()?->getName());
        }

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(PlainSeam::class . ' is no member\'s contract.');

        MemberDefaults::answerOf(PlainSeam::class);
    }
}
