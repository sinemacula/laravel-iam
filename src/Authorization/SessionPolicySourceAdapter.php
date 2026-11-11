<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Authorization;

use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Contracts\ContextualGuard;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authorization\Contracts\SessionPolicySource;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\CredentialScopes;

/**
 * `laravel-authorization`'s session policy source (AUTHZ-13.3), answered from
 * the scopes of the caller's credential as `laravel-authentication` holds them
 * (AUTH-4.5, IAM-6.5): an API key's or a client-credentials token's scopes cap
 * every check about the principal acting with it, and a person's session, which
 * no credential limits, caps nothing. It answers in the order
 * `laravel-authorization`'s contract sets, and fails closed, answering `[]`,
 * wherever it cannot establish the scopes of a credential the subject names.
 *
 * - A subject that says what its credential carries (`Subject::$scopes`), as
 *   the subject resolver fills it from the credential it read
 *   (`SubjectResolverAdapter`), is answered from it: `null` for
 *   `CredentialScopes::uncapped()`, the list for `CredentialScopes::of()`.
 * - A subject that says nothing but names a session is answered `null` while
 *   that session is a live session of the guard the subject names, owned by the
 *   identity the subject acts for: no session stands behind a credential that
 *   carries scopes (an API key and a client-credentials token have none), so a
 *   session carries no cap. The session is looked up for that identity through
 *   `laravel-authentication`'s session service (`SessionService::session()`),
 *   never through the guard's current state. A session that is missing, another
 *   identity's, pending, revoked, expired or of another guard, a subject naming
 *   no guard or acting for no `laravel-authentication` identity, an identity
 *   that holds no sessions, and a guard that is not one of
 *   `laravel-authentication`'s JWT guards, are answered `[]`.
 * - A subject that says nothing and names no session, but names a guard whose
 *   caller is now the subject's own model (the guard's principal or identity,
 *   the same object or the same model), is answered from that caller's
 *   credential (`ContextualGuard::scopes()`): `null` for a person's token, the
 *   list, `[]` included, for an API key or a client-credentials token. Only the
 *   guard the subject names is read, never the default one, and only once it
 *   has resolved its request (`hasUser()`), so its resolution is never started
 *   or entered again from here. A guard that is not configured, or whose
 *   reading throws, is answered `[]`.
 * - Any other subject names no credential: a job's or a console command's, a
 *   model named through `Authorization::for()` (`Subject::withSubject()`), or
 *   one naming a guard whose caller is someone else, or a guard that is not
 *   `laravel-authentication`'s. It is answered `null`, no cap, for a person.
 *
 * A machine is never answered `null` for want of a credential:
 * `laravel-authorization` allows nothing to a machine answered `null` only when
 * the subject carries its own marker (`AuthorizableMachine`), and caps nothing
 * otherwise, while `laravel-authentication`'s machines are its
 * `MachineIdentity`, which does not carry it. So a subject that is a machine
 * identity, whose identity is one, or a principal acting for one, and that
 * names no credential, is answered `[]`, marker or not. A machine's own
 * credential always carries a list (`Caller::$scopes`), so `null` from a
 * credential is left for people alone.
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

        /** Resolves the guard the subject names, and its session service. */
        private AuthFactory $auth,
    ) {}

    /**
     * The scopes the subject's credential carries: those it says, or those of
     * the credential it names, `[]` when they cannot be established; where it
     * names none, `[]` for a machine and `null`, no cap, for anyone else.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return list<string>|null
     *
     * @throws \LogicException
     */
    #[\Override]
    public function scopesFor(Subject $subject): ?array
    {
        if ($subject->scopes !== null) {
            return $subject->scopes->scopes();
        }

        if ($subject->session !== null) {
            return $this->sessionScopes($subject, $subject->session);
        }

        if ($subject->guard !== null) {
            try {
                $guard = $this->auth->guard($subject->guard);

                if ($guard instanceof ContextualGuard && $guard->hasUser() && self::isCaller($guard, $subject->subject)) {
                    return $guard->scopes();
                }
            } catch (\Exception) {
                return [];
            }
        }

        return self::withoutCredential($subject->subject, $subject->identity)->scopes();
    }

    /**
     * The scopes of a subject that names no credential: none granted for one of
     * `laravel-authentication`'s machines, and no cap for anyone else. What a
     * caller deciding about a model without its credential, such as the audit
     * access policy, says of it.
     *
     * @param  object  $subject
     * @param  ?object  $identity
     * @return \SineMacula\Laravel\Authorization\Support\CredentialScopes
     *
     * @throws \LogicException
     */
    public static function withoutCredential(object $subject, ?object $identity = null): CredentialScopes
    {
        return self::isMachine($subject, $identity) ? CredentialScopes::of([]) : CredentialScopes::uncapped();
    }

    /**
     * The scopes of the session the subject names: `null`, no cap, while it is
     * a live session of the subject's guard owned by the identity the subject
     * acts for, and `[]` otherwise.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  string  $session
     * @return list<string>|null
     */
    private function sessionScopes(Subject $subject, string $session): ?array
    {
        try {
            $owner = self::ownerOf($subject);

            if ($subject->guard === null || $owner === null || !$this->auth instanceof AuthManager) {
                return [];
            }

            $summary = $this->auth->sessions($subject->guard)->session($owner, $session);
        } catch (\Exception) {
            return [];
        }

        return $summary !== null && $summary->guard === $subject->guard ? null : [];
    }

    /**
     * The `laravel-authentication` identity the subject acts for: the identity
     * a principal acts for, or the subject itself, and only when the identity
     * the subject names, where it names one, is that same identity; null
     * otherwise.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \LogicException
     */
    private static function ownerOf(Subject $subject): ?Identity
    {
        $model = $subject->subject;
        $owner = $model instanceof Principal ? $model->getIdentity() : $model;

        return $owner instanceof Identity && self::isSame($subject->identity ?? $owner, $owner) ? $owner : null;
    }

    /**
     * Whether the guard's caller is the model: its principal or its identity,
     * the same object or the same model.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\ContextualGuard  $guard
     * @param  object  $model
     * @return bool
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private static function isCaller(ContextualGuard $guard, object $model): bool
    {
        $principal = $guard->principal();

        return $principal !== null && (self::isSame($principal, $model) || self::isSame($guard->identity(), $model));
    }

    /**
     * Whether the two are the same: the same object, or the same model, by its
     * key, table and connection; never when the first is missing.
     *
     * @param  ?object  $held
     * @param  object  $model
     * @return bool
     */
    private static function isSame(?object $held, object $model): bool
    {
        return $held === $model || ($held instanceof Model && $model instanceof Model && $held->is($model));
    }

    /**
     * Whether the subject is one of `laravel-authentication`'s machines: a
     * machine identity itself, or carrying one as its identity, or a principal
     * acting for one.
     *
     * @param  object  $subject
     * @param  ?object  $identity
     * @return bool
     *
     * @throws \LogicException
     */
    private static function isMachine(object $subject, ?object $identity): bool
    {
        return $subject instanceof MachineIdentity
            || $identity instanceof MachineIdentity
            || ($subject instanceof Principal && $subject->getIdentity() instanceof MachineIdentity);
    }
}
