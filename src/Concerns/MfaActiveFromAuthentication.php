<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Concerns;

use SineMacula\Laravel\Authentication\Admission\ActivationPolicy;

/**
 * MFA's active state of an identity, read from `laravel-authentication`'s
 * (IAM-3.12): an identity `laravel-authentication` has deactivated is inactive
 * to MFA too, so MFA refuses it as `identity_inactive` on every path, its
 * challenge counters, factor changes and removals among them, a queued job's or
 * a console's included, not only on the request paths `laravel-authentication`
 * already refuses it on.
 *
 * MFA has no seam for active state: it asks the identity model's
 * `isMfaActive()`, which its `HasFactors` concern answers `true` for every
 * identity. An application identity model that is MFA's and
 * `laravel-authentication`'s uses this concern beside `HasFactors`, choosing
 * this concern's method:
 *
 * ```php
 * use HasFactors, MfaActiveFromAuthentication {
 *     MfaActiveFromAuthentication::isMfaActive insteadof HasFactors;
 * }
 * ```
 *
 * The identity is read through `laravel-authentication`'s own activation
 * policy, so its `isActive()` runs with reads pinned to the write connection,
 * as `laravel-authentication` runs it: a check that reads the database (a
 * suspension row, a lazily loaded relation, a relation on another connection)
 * is never answered by a replica that has not yet seen a deactivation. A model
 * that does not implement `laravel-authentication`'s `CanBeActive` has no
 * active state of its own there, so it is active, as `laravel-authentication`
 * reads it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
trait MfaActiveFromAuthentication
{
    /**
     * Whether the identity is active to MFA: exactly while
     * `laravel-authentication` reads it as active, from the primary.
     *
     * @return bool
     */
    public function isMfaActive(): bool
    {
        return ActivationPolicy::isActive($this);
    }
}
