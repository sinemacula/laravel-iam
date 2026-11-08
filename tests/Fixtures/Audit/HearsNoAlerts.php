<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Audit;

/**
 * A class named as an alert listener that can be handed nothing: it has neither
 * a `handle()` method nor `__invoke()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class HearsNoAlerts {}
