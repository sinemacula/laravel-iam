<?php

declare(strict_types = 1);

namespace Tests\Unit\Tenancy;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Bindings\ConfiguredImplementations;
use SineMacula\Laravel\Iam\Contracts\Memberships;
use SineMacula\Laravel\Iam\Contracts\TenantTree;
use SineMacula\Laravel\Iam\Exceptions\TenancyMisconfiguredException;
use SineMacula\Laravel\Iam\Tenancy\TenancyContracts;
use SineMacula\Laravel\Iam\Testing\FakeMemberships;
use SineMacula\Laravel\Iam\Testing\FakeTenantTree;

/**
 * Unit tests for finding the application's memberships and tenant tree
 * (IAM-7.4, IAM-7.5): the application's binding wins over the class it names
 * (IAM-8.4), a class named is built, neither means none (memberships asked for
 * then throw, a tree is answered as none), and a class named that does not
 * implement the contract, a value that is no class name, or a binding that
 * resolves to no implementation, fails closed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TenancyContracts::class)]
#[CoversClass(ConfiguredImplementations::class)]
#[CoversClass(TenancyMisconfiguredException::class)]
final class TenancyContractsTest extends TestCase
{
    /** @var \Illuminate\Container\Container The container the implementations are bound and built in. */
    private Container $container;

    /** @var \Illuminate\Config\Repository The configuration naming them. */
    private Repository $config;

    /**
     * Start each test with an empty container and the shipped tenancy
     * configuration.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->container = new Container;
        $this->config    = new Repository(['iam' => ['tenancy' => ['memberships' => null, 'tree' => null]]]);
    }

    /**
     * With neither named nor bound, there is no tree, memberships asked for
     * throw rather than answer none, and neither is configured.
     *
     * @return void
     */
    public function testWithNeitherThereIsNoneOfEither(): void
    {
        self::assertNull($this->contracts()->tree());
        self::assertFalse(TenancyContracts::hasMemberships($this->container, $this->config));
        self::assertFalse(TenancyContracts::hasTree($this->container, $this->config));

        $this->expectException(TenancyMisconfiguredException::class);
        $this->expectExceptionMessage('Nothing implements ' . Memberships::class . ': name the class in iam.tenancy.memberships');

        $this->contracts()->memberships();
    }

    /**
     * A class named is built, a fresh one on every call, and counts as
     * configured.
     *
     * @return void
     */
    public function testAClassNamedIsBuilt(): void
    {
        $this->config->set(TenancyContracts::MEMBERSHIPS, FakeMemberships::class);
        $this->config->set(TenancyContracts::TREE, FakeTenantTree::class);

        self::assertInstanceOf(FakeMemberships::class, $this->contracts()->memberships());
        self::assertNotSame($this->contracts()->memberships(), $this->contracts()->memberships());
        self::assertInstanceOf(FakeTenantTree::class, $this->contracts()->tree());
        self::assertTrue(TenancyContracts::hasMemberships($this->container, $this->config));
        self::assertTrue(TenancyContracts::hasTree($this->container, $this->config));
    }

    /**
     * The application's binding wins over the class named, and counts as
     * configured with nothing named.
     *
     * @return void
     */
    public function testTheApplicationsBindingWins(): void
    {
        $memberships = FakeMemberships::fake($this->container);
        $tree        = FakeTenantTree::fake($this->container);

        self::assertTrue(TenancyContracts::hasMemberships($this->container, $this->config));
        self::assertTrue(TenancyContracts::hasTree($this->container, $this->config));

        $this->config->set(TenancyContracts::MEMBERSHIPS, 'App\Missing');
        $this->config->set(TenancyContracts::TREE, 'App\Missing');

        self::assertSame($memberships, $this->contracts()->memberships());
        self::assertSame($tree, $this->contracts()->tree());
    }

    /**
     * Rows of `[value, named]`: what a key may hold, and whether it names
     * anything.
     *
     * @return iterable<string, array{0: mixed, 1: bool}>
     */
    public static function provideNames(): iterable
    {
        yield 'null' => [null, false];

        yield 'empty' => ['', false];

        yield 'blank' => ['   ', false];

        yield 'a class' => [FakeTenantTree::class, true];

        yield 'false' => [false, true];

        yield 'a number' => [1, true];
    }

    /**
     * Only `null` and blank text name nothing; any other value names something,
     * whose kind is checked where it is resolved.
     *
     * @param  mixed  $value
     * @param  bool  $named
     * @return void
     */
    #[DataProvider('provideNames')]
    public function testOnlyNullAndBlankTextNameNothing(mixed $value, bool $named): void
    {
        $this->config->set(TenancyContracts::TREE, $value);

        self::assertSame($named, TenancyContracts::hasTree($this->container, $this->config));
    }

    /**
     * A value that is no class name at all fails closed, naming its type, never
     * the value.
     *
     * @return void
     */
    public function testAValueThatIsNoClassNameFailsClosed(): void
    {
        $this->config->set(TenancyContracts::TREE, true);

        $this->expectException(TenancyMisconfiguredException::class);
        $this->expectExceptionMessage('iam.tenancy.tree holds a value of type [bool], which names no class implementing ' . TenantTree::class);

        $this->contracts()->tree();
    }

    /**
     * A class named that does not implement the contract fails closed.
     *
     * @return void
     */
    public function testAClassThatIsNoImplementationFailsClosed(): void
    {
        $this->config->set(TenancyContracts::MEMBERSHIPS, FakeTenantTree::class);

        $this->expectException(TenancyMisconfiguredException::class);
        $this->expectExceptionMessage('iam.tenancy.memberships names [' . FakeTenantTree::class . '], which is not a class implementing ' . Memberships::class);

        $this->contracts()->memberships();
    }

    /**
     * A binding that resolves to no implementation fails closed, naming the
     * binding.
     *
     * @return void
     */
    public function testABindingThatResolvesToNoImplementationFailsClosed(): void
    {
        $this->container->bind(TenantTree::class, static fn (): object => new \stdClass);

        $this->expectException(TenancyMisconfiguredException::class);
        $this->expectExceptionMessage('The container binding of ' . TenantTree::class . ' resolves to [stdClass], which does not implement ' . TenantTree::class);

        $this->contracts()->tree();
    }

    /**
     * The finder over the container and configuration.
     *
     * @return \SineMacula\Laravel\Iam\Tenancy\TenancyContracts
     */
    private function contracts(): TenancyContracts
    {
        return new TenancyContracts($this->container, $this->config);
    }
}
