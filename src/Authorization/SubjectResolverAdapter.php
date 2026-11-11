<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Authorization;

use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Callers\Caller;
use SineMacula\Laravel\Authentication\Contracts\ContextualGuard;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Resolvers\AuthGuardSubjectResolver;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\CredentialScopes;

/**
 * `laravel-authorization`'s subject resolver, answered from
 * `laravel-authentication`'s caller (IAM-6.1, AUTHZ-13.1): the principal the
 * caller acts as is the subject, with its identity, the active tenant, the
 * application (the guard's name), the session the credential holds and what it
 * says of its scopes.
 *
 * `resolve()` takes nothing, so it reads the request's caller
 * (`Auth::caller()`), as the contract asks of it: the caller's principal, its
 * identity, the tenant the request acts in and the session's key, so the
 * requirement checker judges that very session (`RequirementCheckerAdapter`),
 * and what the credential says of its scopes (`Caller::$scopes`), said on the
 * subject as `CredentialScopes::uncapped()` where none limits it and
 * `CredentialScopes::of()` with the list, `[]` for none granted, where one
 * does, so the session policy source caps the subject's checks by them and
 * looks nothing up (`SessionPolicySourceAdapter`). A request with no caller, or
 * one whose pending session has not chosen a principal, has no subject, and
 * every check without one denies. A credential without a session (an API key, a
 * client-credentials token) gives a subject with none, so no authentication
 * requirement is met for it. `Auth::caller()` is read once per request and kept
 * on the request, so `resolve()` is never asked from inside an admission, which
 * never asks it: application access decides about the principal it is handed
 * (`forUser()`).
 *
 * `forUser()` is handed the model Laravel's Gate decides about, `Auth::user()`
 * (the identity), or one the caller names. It never reads `Auth::caller()`:
 * application access asks it while `laravel-authentication` admits a sign-in, a
 * refresh or a switch, and reading the caller then would prove the request's
 * credential again in the middle of that admission and keep the answer for the
 * rest of the request. The contract hands it the model alone, so it reads the
 * default guard's state, the guard Laravel's Gate takes its user from, only
 * where the guard has already resolved its user: a model that is the guard's
 * principal, or the identity acting as it, is the caller, with the guard's
 * active tenant and session, and its credential's scopes said as `resolve()`
 * says them, whether it is the very object the guard holds or the same model
 * loaded again, so the Gate's checks are capped as the request's own are. Any
 * other principal is a subject with no session, in its own tenant, saying
 * nothing of its scopes. Any other model, an identity that is not the caller's
 * and no principal itself among them, is its own subject and identity, with no
 * tenant and no session, saying nothing of its scopes, as
 * `laravel-authorization`'s own resolver and `Subject::withSubject()` answer
 * it: a decision about it counts only the grants made to it, never those of a
 * principal it acts as, and the grant hook finds such an identity the recipient
 * of a grant made to it (AUTHZ-11.3).
 *
 * A default guard that is not one of `laravel-authentication`'s (a Laravel
 * session guard an admin panel signs in through, say) is answered as
 * `laravel-authorization`'s own resolver answers it, with its application,
 * guard and session, so the application's checks there decide as they did
 * before this package was installed; but a `laravel-authentication` principal,
 * the user that guard holds or one handed in, still acts for its identity and
 * in its own tenant. A user that resolver finds signed in with the request's
 * session on that guard is said to carry what a subject naming no credential
 * carries (`SessionPolicySourceAdapter::withoutCredential()`): no cap for a
 * person, since a Laravel session carries no scopes, and none granted for one
 * of `laravel-authentication`'s machines, which stays closed; left unsaid, the
 * session policy source would take the session key for one of
 * `laravel-authentication`'s sessions, find none, and allow the user nothing.
 * Which guard happens to be the default when the question is asked (a sign-in
 * or refresh route need not name `laravel-authentication`'s) never changes what
 * a principal is allowed: the grants, denials, boundaries and inactive state of
 * its identity reach it on every guard, in application access
 * (`ApplicationAccessAdapter`) too.
 *
 * It holds nothing between calls (IAM-8.1), but is bound scoped, one for a
 * request or job, as `laravel-authorization`'s own default is: the tenant it
 * resolved for the request is kept only while the resolver bound is the one
 * that resolved it (`AuthorizationSeams`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SubjectResolverAdapter implements SubjectResolver
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Auth\Factory  $auth
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Resolves the guards, and the request's caller. */
        private AuthFactory $auth,

        /** The configuration the default guard is named in. */
        private Repository $config,

        /** The container `laravel-authorization`'s own resolver reads the request from. */
        private Container $container,
    ) {}

    /**
     * The request's caller as the subject, or `null` when the request has no
     * caller acting as a principal.
     *
     * @return ?\SineMacula\Laravel\Authorization\Subject
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    #[\Override]
    public function resolve(): ?Subject
    {
        if (!$this->auth instanceof AuthManager || !$this->auth->guard() instanceof ContextualGuard) {
            $subject = $this->guardResolver()->resolve();

            return $subject === null ? null : self::actingForItsIdentity($subject);
        }

        $caller    = $this->auth->caller();
        $principal = $caller?->principal;

        return $caller === null || $principal === null ? null : self::callerSubject($caller, $principal);
    }

    /**
     * The model handed in as the subject: the caller, with its tenant, session
     * and credential's scopes, when it is the default guard's principal or the
     * identity acting as it; otherwise a principal acting for its identity in
     * its own tenant, or any other model, an identity that is no principal
     * included, as its own subject, with no session, saying nothing of its
     * scopes.
     *
     * @param  object  $user
     * @return \SineMacula\Laravel\Authorization\Subject
     */
    #[\Override]
    public function forUser(object $user): Subject
    {
        $guard = $this->auth->guard();

        if (!$guard instanceof ContextualGuard) {
            return self::actingForItsIdentity($this->guardResolver()->forUser($user));
        }

        $name      = $this->defaultGuard();
        $principal = $guard->hasUser() ? $guard->principal() : null;
        $identity  = $principal === null ? null : $guard->identity();

        if ($principal !== null && (self::isSameModel($user, $principal) || self::isSameModel($user, $identity))) {
            return new Subject($principal, $identity, $guard->tenant(), $name, $name, self::sessionKey($guard->session()), self::scopesOf($guard->scopes()));
        }

        return $user instanceof Principal
            ? new Subject($user, $user->getIdentity(), $user->getTenant(), $name, $name)
            : new Subject($user, $user, null, $name, $name);
    }

    /**
     * The caller as the subject: its principal, its identity, the active
     * tenant, its guard as the application, the key of its session and the
     * scopes its credential carries.
     *
     * @param  \SineMacula\Laravel\Authentication\Callers\Caller  $caller
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return \SineMacula\Laravel\Authorization\Subject
     */
    private static function callerSubject(Caller $caller, Principal $principal): Subject
    {
        return new Subject($principal, $caller->identity, $caller->tenant, $caller->guard, $caller->guard, self::sessionKey($caller->session), self::scopesOf($caller->scopes));
    }

    /**
     * The subject `laravel-authorization`'s own resolver answered, acting for
     * the identity behind it and in its own tenant when it is
     * `laravel-authentication`'s principal, with the application, guard and
     * session that resolver found; any other subject as it answered it. A
     * subject signed in with the request's session on that guard carries no cap
     * if it is a person, since such a session carries no scopes, and none
     * granted if it is a machine; one with no session says nothing of its
     * scopes.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return \SineMacula\Laravel\Authorization\Subject
     */
    private static function actingForItsIdentity(Subject $subject): Subject
    {
        $model     = $subject->subject;
        $principal = $model instanceof Principal ? $model : null;
        $identity  = $principal        === null ? $subject->identity : $principal->getIdentity();
        $tenant    = $principal        === null ? $subject->tenant : $principal->getTenant();
        $scopes    = $subject->session === null ? null : SessionPolicySourceAdapter::withoutCredential($model, $identity);

        return new Subject($model, $identity, $tenant, $subject->application, $subject->guard, $subject->session, $scopes);
    }

    /**
     * What the credential says about its scopes: no cap for `null`, and the
     * scopes given, an empty list allowing nothing, otherwise.
     *
     * @param  ?list<string>  $scopes
     * @return \SineMacula\Laravel\Authorization\Support\CredentialScopes
     *
     * @throws \InvalidArgumentException
     */
    private static function scopesOf(?array $scopes): CredentialScopes
    {
        return $scopes === null ? CredentialScopes::uncapped() : CredentialScopes::of($scopes);
    }

    /**
     * Whether the model handed in is the one the guard holds: the same object,
     * or the same model, by its key, table and connection, so a copy of the
     * caller loaded again (`Auth::user()->fresh()`, `User::find(Auth::id())`)
     * is still the caller; never when the guard holds none.
     *
     * @param  object  $user
     * @param  ?object  $held
     * @return bool
     */
    private static function isSameModel(object $user, ?object $held): bool
    {
        return $user === $held || ($user instanceof Model && $held instanceof Model && $user->is($held));
    }

    /**
     * The session's key as text, or `null` for no session, or one whose key is
     * neither a string nor an integer.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @return ?string
     */
    private static function sessionKey(?Session $session): ?string
    {
        $key = $session?->getSessionIdentifier();

        return is_string($key) || is_int($key) ? (string) $key : null;
    }

    /**
     * The name of the default guard, the one Laravel's Gate takes its user
     * from.
     *
     * @return string
     */
    private function defaultGuard(): string
    {
        $guard = $this->config->get('auth.defaults.guard');

        return is_string($guard) ? $guard : '';
    }

    /**
     * `laravel-authorization`'s own resolver, for a default guard that is not
     * one of `laravel-authentication`'s.
     *
     * @return \SineMacula\Laravel\Authorization\Resolvers\AuthGuardSubjectResolver
     */
    private function guardResolver(): AuthGuardSubjectResolver
    {
        return new AuthGuardSubjectResolver($this->auth, $this->config, null, $this->container);
    }
}
