<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Bindings\Enums;

use SineMacula\Laravel\Authorization\Diagnostics\Enums\Lifetime as ReportedLifetime;

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

    /**
     * The lifetime `laravel-authorization`'s configuration report names this
     * one by, as an adapter bound with it is declared to that report: a shared
     * adapter is a singleton there.
     *
     * @return \SineMacula\Laravel\Authorization\Diagnostics\Enums\Lifetime
     */
    public function reported(): ReportedLifetime
    {
        return match ($this) {
            self::TRANSIENT => ReportedLifetime::TRANSIENT,
            self::SHARED    => ReportedLifetime::SINGLETON,
            self::SCOPED    => ReportedLifetime::SCOPED,
        };
    }
}
