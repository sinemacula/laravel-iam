<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Bindings\Contracts;

/**
 * A member seam bound with `bindIf()` of a closure the member's provider
 * declares, as laravel-audit-log binds one of its seams.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
interface ClosureSeam {}
