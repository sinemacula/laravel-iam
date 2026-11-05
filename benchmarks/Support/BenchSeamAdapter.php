<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

/**
 * The adapter every fixture seam binds, standing in for the package's own: the
 * binding rule binds it without resolving it, so it implements nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class BenchSeamAdapter {}
