<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Bindings;

use Tests\Fixtures\Bindings\Contracts\ClosureSeam;
use Tests\Fixtures\Bindings\Contracts\PlainSeam;
use Tests\Fixtures\Bindings\Contracts\ScopedSeam;
use Tests\Fixtures\Bindings\Contracts\SharedSeam;
use Tests\Fixtures\Bindings\Contracts\TransientSeam;

/**
 * This package's adapter for every fixture seam.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Adapter implements ClosureSeam, PlainSeam, ScopedSeam, SharedSeam, TransientSeam {}
