<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Audit\Contracts;

use SineMacula\Laravel\AuditLog\Contracts\DefinesAuditEvents;

/**
 * A code of this package's whose definition lists every property it keeps, as
 * captured or as a keyed hash, and drops any other: the mappers describe an
 * event with exactly these, so a record never carries a property only to have
 * it dropped, nor audit-log's note that one was.
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
