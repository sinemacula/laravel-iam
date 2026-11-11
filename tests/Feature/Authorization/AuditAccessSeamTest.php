<?php

declare(strict_types = 1);

namespace Tests\Feature\Authorization;

use Illuminate\Config\Repository;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Access\DenyAllPolicy;
use SineMacula\Laravel\AuditLog\AuditLogServiceProvider;
use SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy;
use SineMacula\Laravel\Iam\Authorization\AuditAccessPolicyAdapter;
use SineMacula\Laravel\Iam\Authorization\AuthorizationSeams;
use SineMacula\Laravel\Iam\Bindings\BindingOutcome;
use SineMacula\Laravel\Iam\Bindings\Enums\Lifetime;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use Tests\Concerns\PermutesProviderOrder;
use Tests\TestCase;

/**
 * Feature tests for audit-log's access policy answered from
 * `laravel-authorization`'s grants (IAM-6.10, IAM-8.4): bound over audit-log's
 * `DenyAllPolicy` in every provider order, shared, as audit-log's own is; kept
 * where the application binds its own, before any provider registers or once
 * every provider has; never mandatory; and left on `DenyAllPolicy` with the
 * authorization capability's switch off.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationSeams::class)]
final class AuditAccessSeamTest extends TestCase
{
    use PermutesProviderOrder;

    /**
     * The adapter is bound over audit-log's default in every provider order,
     * one for the application.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testThePolicyIsBoundOverAuditLogsDefaultInEveryProviderOrder(array $providers): void
    {
        $this->bootInOrder($providers);

        $policy = $this->policy();

        self::assertInstanceOf(AuditAccessPolicyAdapter::class, $policy);
        self::assertSame($policy, $this->policy());
        self::assertContains(AuditAccessPolicy::class, $this->outcome()->bound);
    }

    /**
     * The application's own policy, bound before any provider registers, is
     * kept in every provider order.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testTheApplicationsPolicyBoundFirstIsKept(array $providers): void
    {
        $own = \Mockery::mock(AuditAccessPolicy::class);

        $this->bootInOrder($providers, before: [AuditAccessPolicy::class => static fn (): AuditAccessPolicy => $own]);

        self::assertSame($own, $this->policy());
        self::assertContains(AuditAccessPolicy::class, $this->outcome()->kept);
    }

    /**
     * The application's own policy, bound once every provider has registered,
     * wins in every provider order.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideProviderOrders')]
    public function testTheApplicationsPolicyBoundLastWins(array $providers): void
    {
        $own = \Mockery::mock(AuditAccessPolicy::class);

        $this->bootInOrder($providers, after: [AuditAccessPolicy::class => static fn (): AuditAccessPolicy => $own]);

        self::assertSame($own, $this->policy());
    }

    /**
     * With the switch off, audit-log keeps its own default.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[WithConfig(AuthorizationSeams::SWITCH, false, defer: false)]
    public function testTheSwitchOffKeepsDenyAll(): void
    {
        self::assertInstanceOf(DenyAllPolicy::class, $this->policy());
    }

    /**
     * The row is shared, over audit-log's `DenyAllPolicy` as audit-log says,
     * and never mandatory.
     *
     * @return void
     */
    public function testTheRowIsSharedAndNeverMandatory(): void
    {
        $rows = array_filter((new AuthorizationSeams)->seams(new Repository), static fn (SeamBinding $binding): bool => $binding->abstract === AuditAccessPolicy::class);
        $row  = array_values($rows)[0] ?? self::fail('No row binds the policy.');

        self::assertSame(AuditAccessPolicyAdapter::class, $row->adapter);
        self::assertSame(Lifetime::SHARED, $row->lifetime);
        self::assertSame([DenyAllPolicy::class], $row->memberDefaults);
        self::assertSame(AuditLogServiceProvider::class, (new \ReflectionFunction($row->holdsDefault ?? self::fail('The row asks no member.')))->getClosureScopeClass()?->getName());
        self::assertFalse($row->isMandatory());
    }

    /**
     * The policy the container resolves.
     *
     * @return mixed
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function policy(): mixed
    {
        $abstract = AuditAccessPolicy::class;

        return $this->app?->make($abstract);
    }

    /**
     * What the binding rule bound and kept.
     *
     * @return \SineMacula\Laravel\Iam\Bindings\BindingOutcome
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function outcome(): BindingOutcome
    {
        $outcome = $this->app?->make(BindingOutcome::class);

        self::assertInstanceOf(BindingOutcome::class, $outcome);

        return $outcome;
    }
}
