<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\HasSessions;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Iam\Exceptions\SessionMismatchException;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\Translation\SignIn;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;

/**
 * Resolves the application and sign-in MFA names to a `jwt` guard's session.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CurrentSession
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Auth\Factory  $auth
     */
    public function __construct(

        /** Resolves the guards. */
        private AuthFactory $auth,
    ) {}

    /**
     * The guard's current session, if it is the identity's named sign-in.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $session
     * @return \SineMacula\Laravel\Authentication\Contracts\Session
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Iam\Exceptions\SessionMismatchException
     */
    public function of(MultiFactorAuthenticatable $identity, string $application, string $session): Session
    {
        $current = $this->current($identity, $application);

        self::assertIsTheSignIn(SignIn::reference($current, $application), $application, $session);

        return $current;
    }

    /**
     * The identity's named session on the guard, whatever the guard holds.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $session
     * @return \SineMacula\Laravel\Authentication\Contracts\Session
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    public function named(MultiFactorAuthenticatable $identity, string $application, string $session): Session
    {
        $this->guard($application);

        $found = $this->owned($this->identity($identity), $session);

        return $found !== null && $found->getGuard() === $application ? $found : throw UnresolvedReferenceException::forSignIn($application);
    }

    /**
     * The identity's session with the key on any guard, if it has one.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $session
     * @return (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession)|null
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function owned(Identity $identity, string $session): (EloquentSession&Model)|null
    {
        return $identity instanceof HasSessions ? Auth::sessions()->sessionRecord($identity, $session) : null;
    }

    /**
     * The guard's current session, which must be the identity's.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return \SineMacula\Laravel\Authentication\Contracts\Session
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    public function current(MultiFactorAuthenticatable $identity, string $application): Session
    {
        return $this->held($identity, $application) ?? throw UnresolvedReferenceException::forSession($application);
    }

    /**
     * The guard's current session, when it is the identity's.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Session
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function held(MultiFactorAuthenticatable $identity, string $application): ?Session
    {
        $guard   = $this->guard($application);
        $session = $guard->session();
        $owner   = $guard->identity();

        return $owner !== null && ProofOwner::of($owner)->is(ProofOwner::of($identity)) ? $session : null;
    }

    /**
     * The identity MFA asks about, as `laravel-authentication`'s identity.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    public function identity(MultiFactorAuthenticatable $identity): Identity
    {
        if (!$identity instanceof Identity) {
            throw UnresolvedReferenceException::forIdentity($identity::class);
        }

        return $identity;
    }

    /**
     * The identity the guard serves, for the testing helper handed no caller.
     *
     * @param  string  $application
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity&\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    public function caller(string $application): Identity&MultiFactorAuthenticatable
    {
        $identity = $this->guard($application)->identity();

        return $identity instanceof MultiFactorAuthenticatable ? $identity : throw UnresolvedReferenceException::forSession($application);
    }

    /**
     * The `jwt` guard the application names.
     *
     * @param  string  $application
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    public function guard(string $application): JwtGuard
    {
        $guard = in_array($application, Auth::sessionGuards(), true) ? $this->auth->guard($application) : null;

        return $guard instanceof JwtGuard ? $guard : throw UnresolvedReferenceException::forGuard($application);
    }

    /**
     * The session service of the `jwt` guard the application names.
     *
     * @param  string  $application
     * @return \SineMacula\Laravel\Authentication\Sessions\SessionService
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    public function sessions(string $application): SessionService
    {
        $this->guard($application);

        return Auth::sessions($application);
    }

    /**
     * Refuse the guard's current session when it is not the sign-in named.
     *
     * @param  string  $current
     * @param  string  $application
     * @param  string  $session
     * @return void
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\SessionMismatchException
     */
    private static function assertIsTheSignIn(string $current, string $application, string $session): void
    {
        if ($current === $session) {
            return;
        }

        throw SessionMismatchException::forGuard($application);
    }
}
