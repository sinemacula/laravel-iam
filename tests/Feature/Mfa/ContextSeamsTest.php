<?php

declare(strict_types = 1);

namespace Tests\Feature\Mfa;

use Illuminate\Config\Repository;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Iam\Bindings\Enums\Lifetime;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use SineMacula\Laravel\Iam\Mfa\ActiveStateResolverAdapter;
use SineMacula\Laravel\Iam\Mfa\ActiveTenantResolverAdapter;
use SineMacula\Laravel\Iam\Mfa\ApplicationResolverAdapter;
use SineMacula\Laravel\Iam\Mfa\ContextSeams;
use SineMacula\Laravel\Iam\Mfa\EventContextResolverAdapter;
use SineMacula\Laravel\Iam\Mfa\MfaSeams;
use SineMacula\Laravel\Iam\Mfa\SubjectTypeResolverAdapter;
use SineMacula\Laravel\Iam\Tenancy\TenancySeams;
use SineMacula\Laravel\Mfa\Context\DefaultEventContextResolver;
use SineMacula\Laravel\Mfa\Context\IdentityContractActiveState;
use SineMacula\Laravel\Mfa\Context\IdentityContractSubjectType;
use SineMacula\Laravel\Mfa\Contracts\ActiveStateResolver;
use SineMacula\Laravel\Mfa\Contracts\ActiveTenantResolver;
use SineMacula\Laravel\Mfa\Contracts\ApplicationResolver;
use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver;
use SineMacula\Laravel\Mfa\Requirements\NoActiveTenant;
use Tests\TestCase;

/**
 * Feature tests for the seams MFA reads its context through.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ContextSeams::class)]
final class ContextSeamsTest extends TestCase
{
    /** @var array<class-string, class-string> Each seam, with the adapter bound over it. */
    private const array ADAPTERS = [
        EventContextResolver::class => EventContextResolverAdapter::class,
        ActiveTenantResolver::class => ActiveTenantResolverAdapter::class,
        SubjectTypeResolver::class  => SubjectTypeResolverAdapter::class,
        ActiveStateResolver::class  => ActiveStateResolverAdapter::class,
        ApplicationResolver::class  => ApplicationResolverAdapter::class,
    ];

    /** @var array<class-string, class-string> Each seam MFA binds, with its default. */
    private const array MEMBER_DEFAULTS = [
        EventContextResolver::class => DefaultEventContextResolver::class,
        ActiveTenantResolver::class => NoActiveTenant::class,
        SubjectTypeResolver::class  => IdentityContractSubjectType::class,
        ActiveStateResolver::class  => IdentityContractActiveState::class,
    ];

    /**
     * Every adapter is bound, MFA's unbound application resolver included.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEveryAdapterIsBound(): void
    {
        foreach (self::ADAPTERS as $abstract => $adapter) {
            self::assertInstanceOf($adapter, $this->app?->make($abstract), $abstract);
        }
    }

    /**
     * With MFA's switch off each member keeps its default.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[WithConfig(MfaSeams::SWITCH, false, defer: false)]
    public function testTheSwitchOffBindsNothing(): void
    {
        foreach (self::MEMBER_DEFAULTS as $abstract => $default) {
            self::assertInstanceOf($default, $this->app?->make($abstract), $abstract);
        }

        self::assertFalse($this->app?->bound(ApplicationResolver::class));
    }

    /**
     * Every binding is transient and none is mandatory without a tenant's rule.
     *
     * @return void
     */
    public function testEveryBindingIsTransientAndOptionalWithoutATenantsRule(): void
    {
        $bindings = (new ContextSeams)->seams(new Repository);

        self::assertSame(self::ADAPTERS, array_combine(
            array_map(static fn (SeamBinding $binding): string => $binding->abstract, $bindings),
            array_map(static fn (SeamBinding $binding): string => $binding->adapter, $bindings),
        ));

        foreach ($bindings as $binding) {
            self::assertSame(Lifetime::TRANSIENT, $binding->lifetime, $binding->abstract);
            self::assertFalse($binding->isMandatory(), $binding->abstract);
        }
    }

    /**
     * The active tenant's resolver alone is mandatory while SSO enforces.
     *
     * @return void
     */
    public function testTheActiveTenantIsMandatoryWhileSsoEnforces(): void
    {
        $config = new Repository;

        $config->set(TenancySeams::ENFORCEMENT, true);

        foreach ((new ContextSeams)->seams($config) as $binding) {
            self::assertSame($binding->abstract === ActiveTenantResolver::class, $binding->isMandatory(), $binding->abstract);
        }
    }

    /**
     * Rows of `[value, on]` for MFA's capability switch.
     *
     * @return iterable<string, array{0: mixed, 1: bool}>
     */
    public static function provideSwitchValues(): iterable
    {
        yield 'missing' => [null, true];

        yield 'on' => ['on', true];

        yield 'off' => ['off', false];

        yield 'false' => [false, false];
    }

    /**
     * Every binding follows MFA's capability switch.
     *
     * @param  mixed  $value
     * @param  bool  $on
     * @return void
     */
    #[DataProvider('provideSwitchValues')]
    public function testEveryBindingFollowsTheMfaSwitch(mixed $value, bool $on): void
    {
        $config = new Repository(['iam' => ['adapters' => ['mfa' => $value]]]);

        foreach ((new ContextSeams)->seams($config) as $binding) {
            self::assertSame($on, $binding->on, $binding->abstract);
        }
    }
}
