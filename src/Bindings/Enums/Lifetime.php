<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Bindings\Enums;

/**
 * How long the container keeps an adapter the binding rule binds over a
 * member's seam.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum Lifetime: string
{
    // A new instance every time the seam is resolved (`bind()`)
    case TRANSIENT = 'transient';

    // One instance for the life of the application (`singleton()`)
    case SHARED = 'shared';

    // One instance per request or job, forgotten between them (`scoped()`)
    case SCOPED = 'scoped';
}
