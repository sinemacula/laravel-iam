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
 * Answers `laravel-authorization`'s subject resolver from
 * `laravel-authentication`'s caller, its tenant, session and credential scopes.
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
     * The request's caller as the subject, or `null` without a principal.
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
     * The model as the subject, with the session when it is the caller.
     *
     * @param  object  $user
     * @return \SineMacula\Laravel\Authorization\Subject
     */
    #[\Override]
    public function forUser(object $user): Subject
    {
        // No `Auth::caller()`: application access asks this mid-admission.
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
     * The caller as the subject.
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
     * A foreign guard's subject, a principal acting for its identity.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return \SineMacula\Laravel\Authorization\Subject
     */
    private static function actingForItsIdentity(Subject $subject): Subject
    {
        $model     = $subject->subject;
        $principal = $model instanceof Principal ? $model : null;
        $identity  = $principal === null ? $subject->identity : $principal->getIdentity();
        $tenant    = $principal === null ? $subject->tenant : $principal->getTenant();

        // Unsaid, the policy source would find no session and allow nothing.
        $scopes = $subject->session === null ? null : SessionPolicySourceAdapter::withoutCredential($model, $identity);

        return new Subject($model, $identity, $tenant, $subject->application, $subject->guard, $subject->session, $scopes);
    }

    /**
     * The credential scopes given, uncapped for `null`.
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
     * Whether the model is the one held, or the same model loaded again.
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
     * The session's key as text, or `null`.
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
     * The default guard's name, which Laravel's Gate takes its user from.
     *
     * @return string
     */
    private function defaultGuard(): string
    {
        $guard = $this->config->get('auth.defaults.guard');

        return is_string($guard) ? $guard : '';
    }

    /**
     * `laravel-authorization`'s own resolver, for a foreign default guard.
     *
     * @return \SineMacula\Laravel\Authorization\Resolvers\AuthGuardSubjectResolver
     */
    private function guardResolver(): AuthGuardSubjectResolver
    {
        return new AuthGuardSubjectResolver($this->auth, $this->config, null, $this->container);
    }
}
