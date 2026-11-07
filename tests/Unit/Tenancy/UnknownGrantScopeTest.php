<?php

declare(strict_types = 1);

namespace Tests\Unit\Tenancy;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Tenancy\UnknownGrantScope;
use SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict;
use Tests\Fixtures\Models\Person;

/**
 * Unit tests for the grant half of SSO's principal scope until
 * `laravel-authorization`'s grant scope query ships (IAM-6.8, Q9): it answers
 * `unknown` for every identity and tenant, never `within_tenant`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(UnknownGrantScope::class)]
final class UnknownGrantScopeTest extends TestCase
{
    /**
     * Every identity's grants are `unknown` against every tenant.
     *
     * @return void
     */
    public function testEveryIdentitysGrantsAreUnknown(): void
    {
        $scope = new UnknownGrantScope;

        self::assertSame(ScopeVerdict::UNKNOWN, $scope->judge(new Person, 'tenant-1'));
        self::assertSame(ScopeVerdict::UNKNOWN, $scope->judge(new Person, 'tenant-2'));
    }
}
