<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Testing\Enums;

/**
 * An enum backed by integers, which the log writes by its value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum Ranked: int
{
    case FIRST = 1;
}
