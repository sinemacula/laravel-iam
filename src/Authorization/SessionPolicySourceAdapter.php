<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Authorization;

use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authorization\Contracts\SessionPolicySource;
use SineMacula\Laravel\Authorization\Subject;

/**
 * `laravel-authorization`'s session policy source (AUTHZ-13.3), answered from
 * the scopes of the caller's credential as `laravel-authentication` holds them
 * (AUTH-4.5, IAM-6.5): an API key's or a client-credentials token's scopes cap
 * every check about the principal acting with it, and a person's session, which
 * no credential limits, caps nothing.
 *
 * The scopes are the subject's own (`Subject::$scopes`), which the subject
 * resolver fills from the credential it read (`SubjectResolverAdapter`, from
 * `Caller::$scopes`), so the source is handed them as a plain value and reads
 * no guard: `null` where no credential limits the subject, a person's session
 * among them, and a list, `[]` allowing nothing, where one does. A subject the
 * caller names for another model (`Authorization::for()`, through
 * `Subject::withSubject()`) is no request's credential and carries none, so it
 * is answered `null`, no cap, as `laravel-authorization`'s contract asks of a
 * person.
 *
 * A machine is never answered `null`: `laravel-authorization` allows nothing to
 * a machine answered `null` only when the subject carries its own marker
 * (`AuthorizableMachine`), and caps nothing otherwise, while
 * `laravel-authentication`'s machines are its `MachineIdentity`, which does not
 * carry it. So a subject that is a machine identity, whose identity is one, or
 * a principal acting for one, and that carries no scopes, is answered `[]`, a
 * cap allowing nothing, marker or not, and a machine never goes uncapped for
 * want of them. A machine's own credential always carries a list
 * (`Caller::$scopes`), so `null` is left for people alone.
 *
 * It holds nothing between calls (IAM-8.1), so it is bound transient.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SessionPolicySourceAdapter implements SessionPolicySource
{
    /**
     * The scopes the subject's credential carries; where it carries none, `[]`
     * for a machine and `null`, no cap, for anyone else.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return list<string>|null
     *
     * @throws \LogicException
     */
    #[\Override]
    public function scopesFor(Subject $subject): ?array
    {
        return $subject->scopes ?? (self::isMachine($subject) ? [] : null);
    }

    /**
     * Whether the subject is one of `laravel-authentication`'s machines: a
     * machine identity itself, or carrying one as its identity, or a principal
     * acting for one.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return bool
     *
     * @throws \LogicException
     */
    private static function isMachine(Subject $subject): bool
    {
        return $subject->subject instanceof MachineIdentity
            || $subject->identity instanceof MachineIdentity
            || ($subject->subject instanceof Principal && $subject->subject->getIdentity() instanceof MachineIdentity);
    }
}
