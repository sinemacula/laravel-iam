<?php

declare(strict_types = 1);

namespace Tests\Feature\Authorization;

use Illuminate\Config\Repository;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Access\DenyAllPolicy;
use SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy;
use SineMacula\Laravel\Iam\Authorization\AuditAccessPolicyAdapter;
use SineMacula\Laravel\Iam\Authorization\AuthorizationSeams;
use SineMacula\Laravel\Iam\Bindings\Enums\Lifetime;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use Tests\TestCase;

/**
 * Feature tests for audit-log's access policy answered from grants.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationSeams::class)]
final class AuditAccessSeamTest extends TestCase
{
    /**
     * The adapter is bound over audit-log's default, one for the application.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testThePolicyIsBoundOverAuditLogsDefault(): void
    {
        $policy = $this->policy();

        self::assertInstanceOf(AuditAccessPolicyAdapter::class, $policy);
        self::assertSame($policy, $this->policy());
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
     * The row is shared and never mandatory.
     *
     * @return void
     */
    public function testTheRowIsSharedAndNeverMandatory(): void
    {
        $rows = array_filter((new AuthorizationSeams)->seams(new Repository), static fn (SeamBinding $binding): bool => $binding->abstract === AuditAccessPolicy::class);
        $row  = array_values($rows)[0] ?? self::fail('No row binds the policy.');

        self::assertSame(AuditAccessPolicyAdapter::class, $row->adapter);
        self::assertSame(Lifetime::SHARED, $row->lifetime);
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
        return $this->app?->make(AuditAccessPolicy::class);
    }
}
