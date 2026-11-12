<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Audit\Contracts;

use SineMacula\Laravel\AuditLog\Contracts\DefinesAuditEvents;

/**
 * A code whose definition lists every property it keeps, so the mappers hand a
 * record exactly those.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
interface ListsProperties extends DefinesAuditEvents
{
    /**
     * Every property the code's definition keeps.
     *
     * @return list<string>
     */
    public function properties(): array;
}
