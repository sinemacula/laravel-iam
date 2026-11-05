<?php

declare(strict_types = 1);

namespace Tests\Unit\Bindings;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Bindings\BindingOutcome;
use Tests\Fixtures\Bindings\Contracts\ClosureSeam;
use Tests\Fixtures\Bindings\Contracts\PlainSeam;
use Tests\Fixtures\Bindings\Contracts\SharedSeam;

/**
 * Unit tests for reporting what one run of the binding rule bound and kept.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(BindingOutcome::class)]
final class BindingOutcomeTest extends TestCase
{
    /**
     * An outcome reports the seams it bound and the seams it kept, each in the
     * order given.
     *
     * @return void
     */
    public function testAnOutcomeReportsTheSeamsBoundAndKept(): void
    {
        $outcome = new BindingOutcome([SharedSeam::class, PlainSeam::class], [ClosureSeam::class]);

        self::assertSame([SharedSeam::class, PlainSeam::class], $outcome->bound);
        self::assertSame([ClosureSeam::class], $outcome->kept);
    }
}
