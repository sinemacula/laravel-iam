<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;

/**
 * Unit tests for what an adapter could not resolve.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReferenceKind::class)]
final class ReferenceKindTest extends TestCase
{
    /**
     * Each kind of reference has its value, and there are no others.
     *
     * @return void
     */
    public function testEachKindHasItsValue(): void
    {
        self::assertSame(['tenant', 'identity', 'principal', 'session', 'guard'], array_map(static fn (ReferenceKind $kind): string => $kind->value, ReferenceKind::cases()));
    }
}
