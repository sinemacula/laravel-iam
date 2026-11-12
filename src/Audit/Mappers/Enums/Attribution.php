<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Audit\Mappers\Enums;

/**
 * Who a mapped event's record says acted when the event names no operator.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum Attribution: string
{
    // The identity the event is about acted for itself
    case SUBJECT = 'subject';

    // Explicitly no one, so no contributor fills the caller in
    case NOBODY = 'nobody';

    // Left to the contributors, for an action the member does not say who took
    case CALLER = 'caller';
}
