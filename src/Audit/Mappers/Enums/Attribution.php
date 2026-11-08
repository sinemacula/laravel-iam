<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Audit\Mappers\Enums;

/**
 * Who a mapped event's record says acted, when the event names no operator of
 * its own (IAM-9.4).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum Attribution: string
{
    // The identity the event is about acted on its own behalf: a sign-in, a
    // refresh, a step-up, a verification
    case SUBJECT = 'subject';

    // Explicitly no one: a refused attempt, whose author was never proven, or
    // what the system did by itself (an expiry, a sweep, a detected replay), so
    // no contributor fills an actor in
    case NOBODY = 'nobody';

    // Whoever the record's context says, left to the contributors: the caller
    // already authenticated, or the actor a queued job carries, for an action
    // the member does not say who took (a revocation, an administrator's
    // change)
    case CALLER = 'caller';
}
