<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Bindings\Contracts;

/**
 * A member seam bound with `bindIf()` of a class name, whose adapter is behind
 * a switch the member's own configuration file and environment fill, as a
 * capability switches an adapter by a member's feature switch.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
interface FeatureSeam {}
