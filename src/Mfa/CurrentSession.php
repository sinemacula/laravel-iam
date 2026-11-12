<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\HasSessions;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Database\StorageConnection;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\SessionRecords\SessionKeyShape;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Iam\Exceptions\SessionMismatchException;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\Translation\SignIn;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;

/**
 * Resolves the sign-in MFA names to `laravel-authentication`'s session: the
 * session of the guard the MFA application is, held by the identity MFA asks
 * about, read by its key where MFA names it and the guard's current one where
 * MFA names none.
 *
 * MFA names a sign-in by its application and a string; an application is the
 * guard of the same name, and the sign-in is the key of one of its sessions.
 * Where MFA hands the sign-in, the session is read by that key (`named()`),
 * whatever the guard holds now; where it hands none, the session is the guard's
 * current one (`current()`, `held()`), and where a contract asks for the
 * identity's current sign-in, the named one must be the guard's current one
 * (`of()`). Nothing is guessed (IAM-8.2): an application that is no session
 * guard (no declared guard of `laravel-authentication`'s `jwt` driver, an
 * `api_key` guard included) throws `UnresolvedReferenceException` of the kind
 * `guard` from every method that resolves a guard alike, a sign-in that is no
 * session of the identity's on the guard, a guard holding no session, or one
 * holding another identity's, throws it of the kind `session`, and a guard
 * holding another of the identity's sessions than the current one named throws
 * `SessionMismatchException`, each inside whatever transaction the member
 * opened, so the change it was making rolls back.
 *
 * It is also where every MFA adapter finds the guard it acts on: the guard the
 * application MFA hands it names (`guard()`), the default guard only where MFA
 * names no application (`defaultGuard()`), the session MFA names (`named()`),
 * the guard's current session when it is the identity's MFA hands over
 * (`current()`, `held()`), `laravel-authentication`'s session service for it
 * (`sessions()`), and the session service a change to the identity as a whole
 * goes through, which names no guard (`identitySessions()`), and every guard
 * that holds sessions, for a session named with no guard (`sessionGuards()`),
 * so every adapter refuses the same misconfiguration the same way; SSO's
 * adapters find them here too, with the session SSO's caller names by its key,
 * of whichever guard (`owned()`). No adapter acts for the identity the guard
 * serves, since MFA hands each its caller as plain values; only the testing
 * helper that verifies the acting session, which is handed none, asks for it
 * (`caller()`). It also tells every adapter that asks
 * `laravel-authentication`'s freshness policy how to ask it
 * (`isInTransaction()`): current inside a transaction on the session model's
 * connection, plainly outside one.
 *
 * It reads the guard's state and the sessions on every call and keeps nothing,
 * so it holds no request state between calls (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CurrentSession
{
    /** @var string The guard driver `laravel-authentication` keeps sessions for. */
    private const string SESSION_DRIVER = 'jwt';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Auth\Factory  $auth
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \Illuminate\Database\ConnectionResolverInterface  $database
     */
    public function __construct(

        /** Resolves the guards. */
        private AuthFactory $auth,

        /** The configuration the guards are declared in. */
        private Repository $config,

        /** Resolves the connection the session model lives on. */
        private ConnectionResolverInterface $database,
    ) {}

    /**
     * The guard's current session, when it is the identity's and the sign-in
     * MFA names.
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
     * The session the sign-in MFA names is, read by its key whatever the guard
     * holds now: one of the identity's sessions, of the guard the application
     * names.
     *
     * Where MFA hands the sign-in (a step-up's proof binding, a removal, a
     * change and its judgement, an event's subject), the session is the one it
     * names, never the guard's current one, so a change made from a queued job,
     * a console command or a request served by another guard acts on the
     * sign-in MFA named. It is read through the identity's own `sessions()`
     * relation on the write connection, so another identity's session is never
     * found, and a key that cannot be one of the session model's is not
     * queried. A key that names no session of the identity's, or one of another
     * guard's, throws `UnresolvedReferenceException` of the kind `session`
     * (IAM-8.2). Whether the session is still live and active is
     * `laravel-authentication`'s to judge, under the session's row lock, in the
     * call it is handed to: a read here would be stale by then.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $session
     * @return \SineMacula\Laravel\Authentication\Contracts\Session
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    public function named(MultiFactorAuthenticatable $identity, string $application, string $session): Session
    {
        $this->guard($application);

        $found = $this->owned($this->identity($identity), $session);

        return $found !== null && $found->getGuard() === $application ? $found : throw UnresolvedReferenceException::forSignIn($application);
    }

    /**
     * The identity's session with the key, of whichever guard, or `null` when
     * the identity holds no sessions, the key cannot be one of the session
     * model's (no query is made), or the identity has no such session.
     *
     * It is read through the identity's own `sessions()` relation on the write
     * connection, so another identity's session is never found, plainly and
     * locking nothing. Whether the session is still live and active is
     * `laravel-authentication`'s to judge, in the call it is handed to.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $session
     * @return (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession)|null
     */
    public function owned(Identity $identity, string $session): (EloquentSession&Model)|null
    {
        if (!$identity instanceof HasSessions) {
            return null;
        }

        $query = $identity->sessions();
        $model = $query->getModel();
        $found = SessionKeyShape::matches($model, $session) ? WriteConnection::during($identity, static fn (): mixed => WriteConnection::query($query)->find($session)) : null;

        return $found instanceof EloquentSession ? $found : null;
    }

    /**
     * The guard's current session, whichever sign-in it is, when it is the
     * identity's.
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

        return $owner !== null && (array) ProofOwner::of($owner) === (array) ProofOwner::of($identity) ? $session : null;
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
     * The identity the application's guard serves, when it is one MFA can hold
     * factors for: asked by the testing helper that verifies the acting session
     * alone, never by an adapter, which MFA hands its caller.
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
     * The name of the default guard, as `Auth::shouldUse()` leaves it: the
     * application MFA names when no application resolver names another, and the
     * one it makes a change on when it names none.
     *
     * @return string
     */
    public function defaultGuard(): string
    {
        $guard = $this->config->get('auth.defaults.guard');

        return is_string($guard) ? $guard : '';
    }

    /**
     * The guard the application names, when one is declared under its name and
     * it is one of `laravel-authentication`'s guards of the `jwt` driver, the
     * one kind that holds sessions. Any other, an `api_key` guard included, is
     * a misconfiguration, so every question about a sign-in on it throws the
     * same way, never answered as a guard that holds no session now.
     *
     * @param  string  $application
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    public function guard(string $application): JwtGuard
    {
        $guard = is_array($this->config->get('auth.guards.' . $application)) ? $this->auth->guard($application) : null;

        if (!$guard instanceof JwtGuard) {
            throw UnresolvedReferenceException::forGuard($application);
        }

        return $guard;
    }

    /**
     * `laravel-authentication`'s session service for the application's guard,
     * when it is a declared guard of the `jwt` driver, the one kind that holds
     * sessions.
     *
     * @param  string  $application
     * @return \SineMacula\Laravel\Authentication\Sessions\SessionService
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    public function sessions(string $application): SessionService
    {
        $auth = $this->auth;

        if (!$auth instanceof AuthManager) {
            throw UnresolvedReferenceException::forGuard($application);
        }

        $this->guard($application);

        return $auth->sessions($application);
    }

    /**
     * `laravel-authentication`'s session service for a change to the identity
     * as a whole, which names no session and so no guard: the default guard's
     * when it is a declared guard of the `jwt` driver, and otherwise the first
     * such guard declared, so a change made where the default guard holds no
     * sessions (an admin panel's session guard, a console command, a queued
     * job) still reaches the identity's sessions.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SessionService
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    public function identitySessions(): SessionService
    {
        $default  = $this->defaultGuard();
        $declared = $this->sessionGuards();

        return $this->sessions(in_array($default, $declared, true) ? $default : ($declared[0] ?? $default));
    }

    /**
     * Whether a transaction is open on the connection
     * `laravel-authentication`'s session model lives on (its storage
     * connection, which it refuses a session model off).
     *
     * MFA asks an adapter inside its own transaction on that connection (a
     * factor change, after its locks) and acts on the answer atomically there,
     * so inside one the adapter asks the freshness policy current: the
     * session's row locked until the transaction ends, then its proofs read as
     * committed, so a proof voided before the call never counts and one
     * recorded before it does, whatever the transaction read first. Outside one
     * (MFA's route gate, `Mfa::isFresh()`, its contract kits) nothing acts on
     * the answer atomically, and the policy refuses a current judgement there,
     * so the adapter asks plainly and locks nothing. This is the line
     * `laravel-authentication`'s own reads of a session's proofs and first
     * factor draw too.
     *
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public function isInTransaction(): bool
    {
        return $this->database->connection(StorageConnection::name())->transactionLevel() > 0;
    }

    /**
     * The names of the guards declared with the `jwt` driver, the one kind that
     * holds sessions, in the order they are declared.
     *
     * @return list<string>
     */
    public function sessionGuards(): array
    {
        $guards = $this->config->get('auth.guards');
        $named  = [];

        foreach (is_array($guards) ? $guards : [] as $name => $guard) {

            if (!is_array($guard) || ($guard['driver'] ?? null) !== self::SESSION_DRIVER) {
                continue;
            }

            $named[] = (string) $name;
        }

        return $named;
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
