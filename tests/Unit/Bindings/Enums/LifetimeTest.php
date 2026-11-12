<?php

declare(strict_types = 1);

namespace Tests\Unit\Bindings\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\Lifetime as ReportedLifetime;
use SineMacula\Laravel\Iam\Bindings\Enums\Lifetime;

/**
 * Unit tests for the adapter lifetimes and how authorization reports them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Lifetime::class)]
final class LifetimeTest extends TestCase
{
    /**
     * The lifetimes are transient, shared and scoped, each backed by its name.
     *
     * @return void
     */
    public function testTheLifetimesAreTransientSharedAndScoped(): void
    {
        self::assertSame(['transient', 'shared', 'scoped'], array_column(Lifetime::cases(), 'value'));
    }

    /**
     * Each lifetime is reported by its own; shared is reported as singleton.
     *
     * @return void
     */
    public function testEachLifetimeIsReportedByItsOwn(): void
    {
        self::assertSame(ReportedLifetime::TRANSIENT, Lifetime::TRANSIENT->reported());
        self::assertSame(ReportedLifetime::SINGLETON, Lifetime::SHARED->reported());
        self::assertSame(ReportedLifetime::SCOPED, Lifetime::SCOPED->reported());
    }
}
