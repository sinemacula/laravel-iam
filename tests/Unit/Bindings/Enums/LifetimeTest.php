<?php

declare(strict_types = 1);

namespace Tests\Unit\Bindings\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Bindings\Enums\Lifetime;

/**
 * Unit tests for the lifetimes an adapter can be bound with.
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
     * The lifetimes are transient, shared and scoped, in that order, each
     * backed by its name.
     *
     * @return void
     */
    public function testTheLifetimesAreTransientSharedAndScoped(): void
    {
        self::assertSame(['transient', 'shared', 'scoped'], array_column(Lifetime::cases(), 'value'));
    }
}
