<?php

declare(strict_types = 1);

namespace Tests\Unit\Tenancy;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Iam\Contracts\TenantTree;
use SineMacula\Laravel\Iam\Tenancy\SubtreePolicyChanges;
use Tests\Fixtures\Tenancy\LazyTenantTree;
use Tests\TestCase;

/**
 * Unit tests for listing the subtree a change reaches (IAM-7.5) from a tree
 * that answers its descendants lazily: a cycle below the tenant, which never
 * answers the tenant itself, is refused at its first repeat, before any tenant
 * is resolved or judged, rather than pulled from the tree for ever while the
 * change's transaction holds its locks.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SubtreePolicyChanges::class)]
final class SubtreePolicyChangesTest extends TestCase
{
    /**
     * A tree whose descendants below the tenant cycle (two tenants each the
     * other's child) is refused as broken at the first repeat, with no tenant
     * resolved.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACycleBelowTheTenantIsRefusedAtItsFirstRepeat(): void
    {
        $resolver = \Mockery::mock(TenantResolver::class);

        $resolver->expects('resolve')->never();

        $this->app?->instance(TenantResolver::class, $resolver);
        $this->app?->instance(TenantTree::class, new LazyTenantTree(['a' => ['b'], 'b' => ['c'], 'c' => ['b']]));

        $changes = $this->app?->make(SubtreePolicyChanges::class) ?? self::fail('The application has not booted.');

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('repeated or the tenant itself, so it has a cycle or is broken');

        $changes->changed('a');
    }
}
