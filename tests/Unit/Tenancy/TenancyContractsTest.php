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
use SineMacula\Laravel\Iam\Exceptions\TenancyMisconfiguredException;
use SineMacula\Laravel\Iam\Tenancy\TenancyContracts;
use SineMacula\Laravel\Iam\Testing\FakeMemberships;

/**
 * Unit tests for finding the application's memberships (IAM-7.4): the
 * application's binding wins over the class it names (IAM-8.4), a class named
 * is built, neither throws, and anything that is no implementation fails
 * closed.
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
        $this->config    = new Repository(['iam' => ['tenancy' => ['memberships' => null]]]);
    }

    /**
     * With memberships neither named nor bound, asking for them throws rather
     * than answer none.
     *
     * @return void
     */
    public function testWithNoneMembershipsThrow(): void
    {
        self::assertFalse(TenancyContracts::hasMemberships($this->container, $this->config));

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

        self::assertInstanceOf(FakeMemberships::class, $this->contracts()->memberships());
        self::assertNotSame($this->contracts()->memberships(), $this->contracts()->memberships());
        self::assertTrue(TenancyContracts::hasMemberships($this->container, $this->config));
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

        self::assertTrue(TenancyContracts::hasMemberships($this->container, $this->config));

        $this->config->set(TenancyContracts::MEMBERSHIPS, 'App\Missing');

        self::assertSame($memberships, $this->contracts()->memberships());
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

        yield 'a class' => [FakeMemberships::class, true];

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
        $this->config->set(TenancyContracts::MEMBERSHIPS, $value);

        self::assertSame($named, TenancyContracts::hasMemberships($this->container, $this->config));
    }

    /**
     * A value that is no class name at all fails closed, naming its type, never
     * the value.
     *
     * @return void
     */
    public function testAValueThatIsNoClassNameFailsClosed(): void
    {
        $this->config->set(TenancyContracts::MEMBERSHIPS, true);

        $this->expectException(TenancyMisconfiguredException::class);
        $this->expectExceptionMessage('iam.tenancy.memberships holds a value of type [bool], which names no class implementing ' . Memberships::class);

        $this->contracts()->memberships();
    }

    /**
     * A class named that does not implement the contract fails closed.
     *
     * @return void
     */
    public function testAClassThatIsNoImplementationFailsClosed(): void
    {
        $this->config->set(TenancyContracts::MEMBERSHIPS, \stdClass::class);

        $this->expectException(TenancyMisconfiguredException::class);
        $this->expectExceptionMessage('iam.tenancy.memberships names [stdClass], which is not a class implementing ' . Memberships::class);

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
        $this->container->bind(Memberships::class, static fn (): object => new \stdClass);

        $this->expectException(TenancyMisconfiguredException::class);
        $this->expectExceptionMessage('The container binding of ' . Memberships::class . ' resolves to [stdClass], which does not implement ' . Memberships::class);

        $this->contracts()->memberships();
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
