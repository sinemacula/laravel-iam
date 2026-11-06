<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use SineMacula\Laravel\Authentication\Admission\ActivationPolicy;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Mfa\Contracts\ActiveStateResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;

/**
 * MFA's active state of an identity, read from `laravel-authentication`'s
 * (IAM-3.12): an identity `laravel-authentication` can deactivate (one that is
 * its `CanBeActive`) is active to MFA exactly while `laravel-authentication`
 * reads it as active, so MFA refuses one it has deactivated as
 * `identity_inactive` everywhere MFA asks, its challenge counters, factor
 * changes, removals and requirements among them, off request paths too (a
 * queued job's, a console command's), where no bearer token is refused first.
 *
 * The identity is read through `laravel-authentication`'s own activation
 * policy, so its `isActive()` runs with reads pinned to the write connection,
 * as `laravel-authentication` runs it: a check that reads the database (a
 * suspension row, a lazily loaded relation, a relation on another connection)
 * is never answered by a replica that has not yet seen a deactivation. Its own
 * `isMfaActive()` is not asked beside it: `laravel-authentication` is the layer
 * that knows the identity's state, as MFA's contract has it.
 *
 * An identity that is not `CanBeActive` has no active state of
 * `laravel-authentication`'s, so it answers as MFA's own default does, by its
 * `isMfaActive()`.
 *
 * It never throws, and holds nothing between calls (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ActiveStateResolverAdapter implements ActiveStateResolver
{
    /**
     * Whether the identity is active: as `laravel-authentication` reads it,
     * from the primary, when it can deactivate the identity, and otherwise as
     * the identity's own `isMfaActive()` says.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return bool
     */
    #[\Override]
    public function isActive(MultiFactorAuthenticatable $identity): bool
    {
        return $identity instanceof CanBeActive ? ActivationPolicy::isActive($identity) : $identity->isMfaActive();
    }
}
