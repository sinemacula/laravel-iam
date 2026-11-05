<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Bindings\Contracts;

/**
 * A member seam bound with a plain `bind()` of a class name, as laravel-mfa
 * bound its seams before laravel-mfa#90 and as any provider may.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
interface PlainSeam {}
