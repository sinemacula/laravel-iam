<?php

declare(strict_types = 1);

namespace Tests\Unit\Bindings;

use Illuminate\Contracts\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Bindings\Enums\Lifetime;
use SineMacula\Laravel\Iam\Bindings\SeamBinding;
use Tests\Fixtures\Bindings\Adapter;
use Tests\Fixtures\Bindings\Contracts\PlainSeam;
use Tests\Fixtures\Bindings\MemberDefault;

/**
 * Unit tests for declaring one member seam this package binds an adapter over.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SeamBinding::class)]
final class SeamBindingTest extends TestCase
{
    /**
     * Declared with only its seam, adapter and defaults, a binding is
     * transient, always on, and not mandatory.
     *
     * @return void
     */
    public function testABindingIsTransientAlwaysOnAndOptionalByDefault(): void
    {
        $binding = new SeamBinding(PlainSeam::class, Adapter::class, [MemberDefault::class]);

        self::assertSame(PlainSeam::class, $binding->abstract);
        self::assertSame(Adapter::class, $binding->adapter);
        self::assertSame([MemberDefault::class], $binding->memberDefaults);
        self::assertSame(Lifetime::TRANSIENT, $binding->lifetime);
        self::assertNull($binding->appliesWhen);
        self::assertFalse($binding->mandatory);
    }

    /**
     * A binding keeps the lifetime, switch and mandatory flag it is declared
     * with.
     *
     * @return void
     */
    public function testABindingKeepsWhatItIsDeclaredWith(): void
    {
        $switch  = static fn (Repository $config): bool => $config->has('iam');
        $binding = new SeamBinding(PlainSeam::class, Adapter::class, [], Lifetime::SCOPED, $switch, true);

        self::assertSame([], $binding->memberDefaults);
        self::assertSame(Lifetime::SCOPED, $binding->lifetime);
        self::assertSame($switch, $binding->appliesWhen);
        self::assertTrue($binding->mandatory);
    }
}
