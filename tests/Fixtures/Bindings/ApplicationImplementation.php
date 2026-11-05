<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Bindings;

use Tests\Fixtures\Bindings\Contracts\ClosureSeam;
use Tests\Fixtures\Bindings\Contracts\PlainSeam;
use Tests\Fixtures\Bindings\Contracts\SharedSeam;

/**
 * The application's own implementation of every fixture seam.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ApplicationImplementation implements ClosureSeam, PlainSeam, SharedSeam {}
