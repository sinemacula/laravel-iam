<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Authorization;

use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\ContextualGuard;
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
 * The scopes are read from the guard the check's subject names, and only while
 * that guard holds the subject now: its current principal is the subject's, by
 * the same model, and, where the subject carries a session, its current session
 * is that session. Any other subject, one the caller names for another
 * principal (`Authorization::for()`) or for another of the principal's sessions
 * among them, is no credential the guard holds, so it is answered `null`, no
 * cap, as `laravel-authorization`'s contract asks of a person. A subject naming
 * no guard, or a guard that is not one of `laravel-authentication`'s contextual
 * guards, is answered `null` too.
 *
 * A machine is never answered `null`: `laravel-authorization` allows nothing to
 * a machine answered `null` only when the subject carries its own marker
 * (`AuthorizableMachine`), and caps nothing otherwise, while
 * `laravel-authentication`'s machines are its `MachineIdentity`, which does not
 * carry it. So a subject that is a machine identity, whose identity is one, or
 * a principal acting for one, and whose credential the guard does not hold, is
 * answered `[]`, a cap allowing nothing, marker or not, and a machine never
 * borrows scopes it was not issued, nor goes uncapped for want of them. A
 * machine's own guard always answers a list for it
 * (`ContextualGuard::scopes()`), so `null` is left for people alone.
 *
 * The read is ambient, and has to be: `laravel-authentication` hands a
 * credential's scopes to the guard that admitted it (`scopes()`, which
 * `Auth::scopes()` reads for the default guard) and to the request's caller
 * (`Caller::$scopes`), but `laravel-authorization`'s subject, all the source is
 * handed, carries none, and the request's caller is no less ambient a read than
 * the guard, nor names the guard the subject does. It reads only the guard the
 * subject names, never the default one, and reads it afresh on every call, and
 * only once that guard has already resolved its request (`hasUser()`): a guard
 * that has not, or one that is still admitting its request (a principal's
 * application access asked as an API key is admitted), holds no credential yet,
 * so the subject it is asked about is answered as one the guard does not hold,
 * `null` for a person and `[]` for a machine, and the guard's resolution is
 * never started or entered again from here. Whatever the guard throws (an
 * identity that no longer resolves, a guard the subject names that is not
 * configured) propagates, and `laravel-authorization` makes no decision.
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
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Auth\Factory  $auth
     */
    public function __construct(

        /** Resolves the guard the subject names. */
        private AuthFactory $auth,
    ) {}

    /**
     * The scopes of the credential the subject's guard holds for it now; where
     * the guard has resolved no credential yet or holds none of the subject's,
     * `[]` for a machine and `null` for anyone else; `null` too for a
     * credential no scope limits.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return list<string>|null
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     * @throws \LogicException
     */
    #[\Override]
    public function scopesFor(Subject $subject): ?array
    {
        $guard = $subject->guard === null ? null : $this->auth->guard($subject->guard);

        if ($guard instanceof ContextualGuard && $guard->hasUser() && self::holds($guard, $subject)) {
            return $guard->scopes();
        }

        return self::isMachine($subject) ? [] : null;
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

    /**
     * Whether the guard holds the subject now: its current principal is the
     * subject's, and its current session is the one the subject carries, where
     * it carries one.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\ContextualGuard  $guard
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return bool
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private static function holds(ContextualGuard $guard, Subject $subject): bool
    {
        if (!self::isSamePrincipal($guard->principal(), $subject->subject)) {
            return false;
        }

        if ($subject->session === null) {
            return true;
        }

        $session = $guard->session()?->getSessionIdentifier();

        return (is_string($session) || is_int($session)) && (string) $session === $subject->session;
    }

    /**
     * Whether the guard's principal is the subject: the same object, or the
     * same model, by its key, table and connection; never when the guard holds
     * none.
     *
     * @param  ?object  $principal
     * @param  object  $subject
     * @return bool
     */
    private static function isSamePrincipal(?object $principal, object $subject): bool
    {
        return $principal === $subject || ($principal instanceof Model && $subject instanceof Model && $principal->is($subject));
    }
}
