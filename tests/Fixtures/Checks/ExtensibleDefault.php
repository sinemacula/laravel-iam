<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Checks;

use Tests\Fixtures\Bindings\Contracts\PlainSeam;

/**
 * A member's default a class can extend, as the members' own defaults, all
 * final, cannot be, so a check can be shown an anonymous subclass of a member's
 * default.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @inheritable
 *
 * @internal
 */
class ExtensibleDefault implements PlainSeam {}
