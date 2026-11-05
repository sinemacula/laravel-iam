<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Bindings\Contracts;

/**
 * A member seam bound with `scopedIf()` of a class name, as laravel-sso binds
 * its request-scoped seams, behind a switch the application can turn off.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
interface ScopedSeam {}
