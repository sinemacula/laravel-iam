<?php

declare(strict_types = 1);

namespace Tests\Unit\Tenancy;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Iam\Contracts\TenantMfaRequirement;
use SineMacula\Laravel\Iam\Exceptions\TenantMfaRequirementMisconfiguredException;
use SineMacula\Laravel\Iam\Tenancy\TenantMfaRequirements;
use SineMacula\Laravel\Iam\Testing\FakeTenantMfaRequirement;
use Tests\Fixtures\Resolvers\ClaimedTenant;

/**
 * Unit tests for asking the application's tenant MFA requirement (IAM-4.5): the
 * application's binding wins over the class it names (IAM-8.4), a class named
 * is built and asked, neither means no tenant requires a further factor, and a
 * class named that is no requirement, or a binding that resolves to none, fails
 * closed rather than answer that nothing is required.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TenantMfaRequirements::class)]
final class TenantMfaRequirementsTest extends TestCase
{
    /** @var \Illuminate\Container\Container The container the requirement is bound and built in. */
    private Container $container;

    /** @var \Illuminate\Config\Repository The configuration naming the requirement. */
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
        $this->config    = new Repository(['iam' => ['tenancy' => ['mfa_requirement' => null]]]);
    }

    /**
     * With no requirement bound or named, no tenant requires a further factor.
     *
     * @return void
     */
    public function testWithNoRequirementNoTenantRequiresAFactor(): void
    {
        $rule = $this->requirements()->ruleFor(new ClaimedTenant('tenant-1'), 'api');

        self::assertTrue($rule->isEmpty());
        self::assertNull($rule->version);
    }

    /**
     * The class the configuration names is built and asked, for the tenant and
     * the application given.
     *
     * @return void
     */
    public function testTheClassNamedIsAsked(): void
    {
        $this->config->set(TenantMfaRequirements::KEY, FakeTenantMfaRequirement::class);

        $fake = new FakeTenantMfaRequirement;

        $fake->require('tenant-1', self::multifactor());

        $this->container->instance(FakeTenantMfaRequirement::class, $fake);

        self::assertEquals(self::multifactor(), $this->requirements()->ruleFor(new ClaimedTenant('tenant-1'), 'api')->requirement);
        self::assertSame([['tenant' => 'tenant-1', 'application' => 'api']], $fake->asked());
    }

    /**
     * The application's binding of the contract wins over the class it names.
     *
     * @return void
     */
    public function testTheApplicationsBindingWinsOverTheClassNamed(): void
    {
        $this->config->set(TenantMfaRequirements::KEY, 'App\Tenancy\Unbuildable');

        FakeTenantMfaRequirement::fake($this->container)->require('tenant-1', self::multifactor());

        self::assertFalse($this->requirements()->ruleFor(new ClaimedTenant('tenant-1'), 'api')->isEmpty());
    }

    /**
     * The requirement is resolved when it is asked, not when the resolver was
     * built.
     *
     * @return void
     */
    public function testTheRequirementIsTheOneBoundWhenAsked(): void
    {
        $requirements = $this->requirements();

        FakeTenantMfaRequirement::fake($this->container)->require('tenant-1', self::multifactor());

        self::assertFalse($requirements->ruleFor(new ClaimedTenant('tenant-1'), 'api')->isEmpty());
    }

    /**
     * What the application's requirement throws propagates.
     *
     * @return void
     */
    public function testWhatTheRequirementThrowsPropagates(): void
    {
        $failure = new \RuntimeException('The tenant\'s settings cannot be read.');

        FakeTenantMfaRequirement::fake($this->container)->failFor('tenant-1', $failure);

        try {
            $this->requirements()->ruleFor(new ClaimedTenant('tenant-1'), 'api');

            self::fail('The requirement answered.');
        } catch (\RuntimeException $exception) {
            self::assertSame($failure, $exception);
        }
    }

    /**
     * Rows of a value naming no class implementing the contract.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideNoRequirements(): iterable
    {
        yield 'no class' => ['App\Tenancy\Missing'];

        yield 'a class of another kind' => [\stdClass::class];

        yield 'the contract itself' => [TenantMfaRequirement::class];
    }

    /**
     * A class named that does not implement the contract fails closed, naming
     * the key and the class.
     *
     * @param  string  $named
     * @return void
     */
    #[DataProvider('provideNoRequirements')]
    public function testAClassNamedThatIsNoRequirementFailsClosed(string $named): void
    {
        $this->config->set(TenantMfaRequirements::KEY, $named);

        $this->expectException(TenantMfaRequirementMisconfiguredException::class);
        $this->expectExceptionMessage(sprintf('iam.tenancy.mfa_requirement names [%s], which is not a class implementing %s', $named, TenantMfaRequirement::class));

        $this->requirements()->ruleFor(new ClaimedTenant('tenant-1'), 'api');
    }

    /**
     * Rows of `[value, type]`: a configured value that is no class name at all,
     * and the type the failure names.
     *
     * @return iterable<string, array{0: mixed, 1: string}>
     */
    public static function provideValuesThatAreNoClassName(): iterable
    {
        yield 'true' => [true, 'bool'];

        yield 'false' => [false, 'bool'];

        yield 'a number' => [1, 'int'];

        yield 'an array' => [[FakeTenantMfaRequirement::class], 'array'];
    }

    /**
     * A value that is no class name at all is a misconfiguration, never a
     * choice of no requirement: the application has a requirement, and asking
     * it fails closed, naming the key and the value's type, never the value.
     *
     * @param  mixed  $value
     * @param  string  $type
     * @return void
     */
    #[DataProvider('provideValuesThatAreNoClassName')]
    public function testAValueThatIsNoClassNameFailsClosed(mixed $value, string $type): void
    {
        $this->config->set(TenantMfaRequirements::KEY, $value);

        self::assertTrue($this->requirements()->isConfigured());

        $this->expectException(TenantMfaRequirementMisconfiguredException::class);
        $this->expectExceptionMessage(sprintf('iam.tenancy.mfa_requirement holds a value of type [%s], which names no class implementing %s', $type, TenantMfaRequirement::class));

        $this->requirements()->ruleFor(new ClaimedTenant('tenant-1'), 'api');
    }

    /**
     * A binding, of the contract or of the class named, that resolves to what
     * is no requirement fails closed, naming the binding.
     *
     * @return void
     */
    public function testABindingThatResolvesToNoRequirementFailsClosed(): void
    {
        $this->container->bind(TenantMfaRequirement::class, static fn (): object => new \stdClass);

        $this->expectException(TenantMfaRequirementMisconfiguredException::class);
        $this->expectExceptionMessage(sprintf('The container binding of %s resolves to [stdClass]', TenantMfaRequirement::class));

        $this->requirements()->ruleFor(new ClaimedTenant('tenant-1'), 'api');
    }

    /**
     * The class named is blamed for a binding of it that resolves to no
     * requirement.
     *
     * @return void
     */
    public function testABindingOfTheClassNamedThatResolvesToNoRequirementFailsClosed(): void
    {
        $this->config->set(TenantMfaRequirements::KEY, FakeTenantMfaRequirement::class);
        $this->container->bind(FakeTenantMfaRequirement::class, static fn (): object => new \stdClass);

        $this->expectException(TenantMfaRequirementMisconfiguredException::class);
        $this->expectExceptionMessage(sprintf('The container binding of %s resolves to [stdClass]', FakeTenantMfaRequirement::class));

        $this->requirements()->ruleFor(new ClaimedTenant('tenant-1'), 'api');
    }

    /**
     * Rows of `[value, named]`: a configured value, and whether it names a
     * class.
     *
     * @return iterable<string, array{0: mixed, 1: bool}>
     */
    public static function provideNamedValues(): iterable
    {
        yield 'a class' => [FakeTenantMfaRequirement::class, true];

        yield 'any text' => ['App\Tenancy\Missing', true];

        yield 'nothing' => [null, false];

        yield 'empty' => ['', false];

        yield 'blank' => ['   ', false];

        yield 'true' => [true, true];

        yield 'false' => [false, true];

        yield 'a number' => [1, true];

        yield 'an array' => [[FakeTenantMfaRequirement::class], true];
    }

    /**
     * The configuration names a requirement by any value but `null` and blank
     * text, which alone name none.
     *
     * @param  mixed  $value
     * @param  bool  $named
     * @return void
     */
    #[DataProvider('provideNamedValues')]
    public function testARequirementIsNamedByAnyValueButNothingOrBlankText(mixed $value, bool $named): void
    {
        $this->config->set(TenantMfaRequirements::KEY, $value);

        self::assertSame($named, TenantMfaRequirements::isNamed($this->config));
    }

    /**
     * The application has a requirement once it binds one or names one, and not
     * before.
     *
     * @return void
     */
    public function testARequirementIsConfiguredOnceBoundOrNamed(): void
    {
        self::assertFalse($this->requirements()->isConfigured());

        $this->config->set(TenantMfaRequirements::KEY, FakeTenantMfaRequirement::class);

        self::assertTrue($this->requirements()->isConfigured());

        $this->config->set(TenantMfaRequirements::KEY, null);

        FakeTenantMfaRequirement::fake($this->container);

        self::assertTrue($this->requirements()->isConfigured());
    }

    /**
     * The resolver over the test's container and configuration.
     *
     * @return \SineMacula\Laravel\Iam\Tenancy\TenantMfaRequirements
     */
    private function requirements(): TenantMfaRequirements
    {
        return new TenantMfaRequirements($this->container, $this->config);
    }

    /**
     * Multifactor authentication within five minutes.
     *
     * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
     */
    private static function multifactor(): Requirement
    {
        return new Requirement(multifactor: new RequirementPart(300));
    }
}
