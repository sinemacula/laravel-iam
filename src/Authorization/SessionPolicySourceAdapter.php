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
 * Answers `laravel-authorization`'s session policy source from the scopes of
 * the subject's credential, failing closed with `[]` where they are unknown.
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
     * The scopes the subject's credential carries, or `null` for no cap.
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

        return ($this->callerScopes($subject) ?? self::withoutCredential($subject->subject, $subject->identity))->scopes();
    }

    /**
     * Without a credential: no scopes for a machine, no cap for anyone else.
     *
     * @param  object  $subject
     * @param  ?object  $identity
     * @return \SineMacula\Laravel\Authorization\Support\CredentialScopes
     *
     * @throws \LogicException
     */
    public static function withoutCredential(object $subject, ?object $identity = null): CredentialScopes
    {
        // `MachineIdentity` does not carry the `AuthorizableMachine` marker.
        return self::isMachine($subject, $identity) ? CredentialScopes::of([]) : CredentialScopes::uncapped();
    }

    /**
     * The named guard's scopes while its caller is the subject, else `null`.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return ?\SineMacula\Laravel\Authorization\Support\CredentialScopes
     */
    private function callerScopes(Subject $subject): ?CredentialScopes
    {
        try {
            $guard = $subject->guard === null ? null : $this->auth->guard($subject->guard);

            // `hasUser()` keeps the guard's resolution from being re-entered.
            return $guard instanceof ContextualGuard && $guard->hasUser() && self::isCaller($guard, $subject->subject) ? self::carried($guard->scopes()) : null;
        } catch (\Exception) {
            return CredentialScopes::of([]);
        }
    }

    /**
     * The credential scopes given, uncapped for `null`.
     *
     * @param  ?list<string>  $scopes
     * @return \SineMacula\Laravel\Authorization\Support\CredentialScopes
     *
     * @throws \InvalidArgumentException
     */
    private static function carried(?array $scopes): CredentialScopes
    {
        return $scopes === null ? CredentialScopes::uncapped() : CredentialScopes::of($scopes);
    }

    /**
     * `null` while the named session is a live one of the subject's, else `[]`.
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
     * The identity the subject acts for, or `null` when it names another.
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
     * Whether the guard's principal or identity is the model.
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
     * Whether the two are the same object or the same model.
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
     * Whether the subject is, carries or acts for a machine identity.
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
