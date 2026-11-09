<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Requirements\RequirementSubject;
use SineMacula\Laravel\Iam\Exceptions\SessionMismatchException;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\Translation\IdentityReference;
use SineMacula\Laravel\Iam\Mfa\Translation\SignIn;
use SineMacula\Laravel\Iam\Transactions\CrossMemberTransaction;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;

/**
 * MFA's proof store, kept in `laravel-authentication`'s session proofs: a
 * sign-in is the guard's current session, and its proofs are the ones that
 * session records (IAM-3.11).
 *
 * MFA names a sign-in by its application and a string; here the application is
 * the guard of the same name and the sign-in is the key of the guard's current
 * session, so a sign-in made on one request is the same sign-in on the next
 * request that presents a token of the same session, with no Laravel session
 * kept anywhere. The proofs are the session's counting proofs, read through
 * `Auth::sessions($guard)->proofs()`, oldest first, translated to MFA's proofs
 * bound to the sign-in and stamped with the identity's current verification
 * generation. An SSO sign-in's first factor, or a reauthentication at the
 * provider, names its connection to MFA only when it carries evidence SSO's
 * evidence contract accepted and the session's tenant, if any, trusts the
 * connection (`ProviderTrust::accepted()`), so a combination policy that trusts
 * a connection never counts a sign-in SSO's evidence gate refused, nor one
 * tenant's trust for another. The translation is `SignInProofs`, which the
 * `mfa` context contributor shares, so the store and the context read a
 * session's proofs alike; the store reads the guard's current session only
 * because MFA's contract asks for the identity's current sign-in and hands no
 * session to read instead, and `record()`, handed a binding but no identity,
 * finds that identity as the guard is signed in as it.
 *
 * `laravel-authentication` is the only writer of a session's proofs: it records
 * the first factor when the session is signed in, in the same transaction as
 * the session's row, and every further proof MFA verifies reaches it through
 * the step-up and pending completion adapters, as the last write of MFA's
 * transaction. So this store keeps nothing of its own, and owns no data:
 *
 * - `begin()` is a no-op: the session is the sign-in, begun before the guard
 *   is bound and `Login` fires, under a key MFA's listener does not know;
 * - `record()` refuses, by throwing MFA's `ProofRefusedException`, a proof that
 *   is not bound to the identity's current sign-in on a live, active session of
 *   a person, checked with `firstFactor()` in a transaction on the storage
 *   connection, so the session's row is locked until that transaction ends;
 *   on that sign-in it keeps the sign-in's own first factor, which the session
 *   already holds, and refuses any other proof, which only
 *   `laravel-authentication` can record;
 * - `forgetFactor()` writes nothing for a factor MFA has deleted: a proof that
 *   names a factor counts only while the identity still holds that factor in
 *   MFA's factor table, read on the write connection, so the factor stops
 *   counting at once, inside MFA's own transaction, before the session revoker
 *   (IAM-3.7) reports the removal to `factorRemoved()`, which voids the current
 *   session's proofs made with the factor and ends every other session; a
 *   factor the identity still holds is reported to `factorRemoved()` here, so
 *   its proofs stop counting all the same;
 * - `forget()` is a no-op: `laravel-authentication` signs a session out, or
 *   forgets the guard's binding to it, before `Logout` reaches MFA, and whether
 *   a session ends is its decision, not this package's.
 *
 * A guard that holds no session of the identity holds no sign-in of it, so
 * `currentSession()` answers `null` and `proofs()` none, as the contract asks,
 * and nothing counts. An application that is no session guard of
 * `laravel-authentication`'s is a misconfiguration, which `CurrentSession`
 * reports by throwing. A proof the session holds that MFA cannot express (an
 * additional factor that names no factor, say), or that names a factor the
 * identity no longer holds, is left out rather than guessed at. An identity
 * whose key cannot name a proof's owner throws `UnresolvedReferenceException`
 * (IAM-8.2).
 *
 * It holds no state between calls (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ProofStoreAdapter implements ProofStore
{
    /** @var string Why a proof other than the sign-in's own first factor is refused, and what records one instead. */
    private const string RECORDED_ELSEWHERE = 'Only laravel-authentication records a session\'s proofs; a further proof reaches it through a step-up or a pending completion,'
        . ' or, in a test, through InteractsWithIam::actingOnVerifiedSession().';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \SineMacula\Laravel\Iam\Mfa\CurrentSession  $sessions
     * @param  \SineMacula\Laravel\Iam\Mfa\SignInProofs  $proofs
     * @param  \SineMacula\Laravel\Iam\Transactions\CrossMemberTransaction  $transaction
     */
    public function __construct(

        /** The configuration the guards are declared in. */
        private Repository $config,

        /** Resolves the sign-in MFA names to the guard's current session. */
        private CurrentSession $sessions,

        /** Reads the session's proofs as MFA's proofs of the sign-in. */
        private SignInProofs $proofs,

        /** Runs the liveness check in a transaction on the storage connection. */
        private CrossMemberTransaction $transaction,
    ) {}

    /**
     * Begin the identity's sign-in on the application: nothing to do, since the
     * guard's session is the sign-in and `laravel-authentication` began it.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $sessionId
     * @return void
     */
    #[\Override]
    public function begin(MultiFactorAuthenticatable $identity, string $application, string $sessionId): void
    {
        // A session's row is the sign-in: laravel-authentication begins it with
        // its first factor before the guard is bound and `Login` fires, and
        // MFA's listener names it by a fresh id of its own, so there is nothing
        // to begin, check or keep here.
    }

    /**
     * The identity's current sign-in on the application: the key of the guard's
     * current session when it is the identity's, or `null` when the guard holds
     * no session of the identity.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return ?string
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    #[\Override]
    public function currentSession(MultiFactorAuthenticatable $identity, string $application): ?string
    {
        $session = $this->session($identity, $application);

        return $session === null ? null : SignIn::reference($session, $application);
    }

    /**
     * Keep the proof when the identity's current, live sign-in already holds
     * it, and refuse it otherwise.
     *
     * The sign-in must be the guard's current session, held by the identity the
     * proof names, and one of the guard's live, active sessions of a person,
     * checked in a transaction on the storage connection (a savepoint of the
     * caller's, when one is open) that locks the session's row. On it, only the
     * sign-in's own first factor, made with the method and on the kind of
     * channel the session recorded, is kept: the session holds it already. Any
     * other proof reaches the session only through `laravel-authentication`,
     * and is refused.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException
     * @throws \Throwable
     */
    #[\Override]
    public function record(Proof $proof): void
    {
        $this->transaction->run(function () use ($proof): void {

            $session     = $this->signInOf($proof->binding);
            $firstFactor = Auth::sessions($proof->binding->application)->firstFactor($session);

            if ($firstFactor === null) {
                throw new ProofRefusedException('The proof is bound to a session that is no longer live and active, so it cannot be recorded.');
            }

            if (!self::isTheFirstFactor($proof, $firstFactor)) {
                throw new ProofRefusedException(self::RECORDED_ELSEWHERE);
            }
        });
    }

    /**
     * The counting proofs of the identity's current sign-in on the application,
     * oldest first, as MFA's proofs bound to it; none when the guard holds no
     * session of the identity.
     *
     * The newest `RequirementSubject::MAX_LIMIT` proofs are read; MFA's first
     * factor resolver answers the sign-in's first factor whenever it is not
     * among them. A proof that names a factor the identity no longer holds does
     * not count.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \Throwable
     */
    #[\Override]
    public function proofs(MultiFactorAuthenticatable $identity, string $application): array
    {
        $session = $this->session($identity, $application);

        if ($session === null) {
            return [];
        }

        $recorded = Auth::sessions($application)->proofs($session, limit: RequirementSubject::MAX_LIMIT);

        return $this->proofs->of($identity, $application, $session, array_reverse($recorded));
    }

    /**
     * The first factor the identity's current sign-in on the application was
     * made with, as MFA's proof bound to it, or `null` when the guard holds no
     * live, active session of the identity, MFA cannot express it, or it names
     * a factor the identity no longer holds. Inside a transaction on the
     * storage connection, the session's row is locked and the proof read
     * current.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return ?\SineMacula\Laravel\Mfa\Proofs\Proof
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \Throwable
     */
    public function firstFactor(MultiFactorAuthenticatable $identity, string $application): ?Proof
    {
        $session = $this->session($identity, $application);

        if ($session === null) {
            return null;
        }

        $recorded = Auth::sessions($application)->firstFactor($session);

        return $recorded === null ? null : ($this->proofs->of($identity, $application, $session, [$recorded])[0] ?? null);
    }

    /**
     * Stop counting the identity's proofs made with the factor, on the current
     * session as on every other.
     *
     * A factor the identity no longer holds needs nothing written: a proof
     * counts only while the identity holds the factor it names, so once MFA has
     * deleted the factor, as it does before it forgets it, its proofs stop
     * counting at once, and the session revoker (IAM-3.7) then reports the
     * removal to `laravel-authentication`, which voids them for good. Writing
     * here as well would judge the current session twice, and the second
     * judgement would lose the pending credential the first issued.
     *
     * A factor the identity still holds is forgotten through
     * `laravel-authentication`, the only writer of a session's proofs, as the
     * removal it is: `factorRemoved()` on the default guard, since MFA hands
     * this no application as it hands the session revoker one, voids the
     * current session's proofs made with the factor and judges it again, and
     * ends every other session of the identity, every session when that guard
     * holds none of the identity's.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $factorId
     * @return void
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \Throwable
     */
    #[\Override]
    public function forgetFactor(MultiFactorAuthenticatable $identity, string $factorId): void
    {
        if (!SignInProofs::holds($identity, $factorId)) {
            return;
        }

        $guard = $this->sessions->defaultGuard();

        $this->sessions->sessions($guard)->factorRemoved($this->sessions->identity($identity), $factorId, $this->session($identity, $guard));
    }

    /**
     * Forget the identity's sign-in on the application: nothing to do, since
     * `laravel-authentication` signs the session out, or forgets the guard's
     * binding to it, itself.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return void
     */
    #[\Override]
    public function forget(MultiFactorAuthenticatable $identity, string $application): void
    {
        // laravel-authentication revokes the session, or forgets the guard's
        // binding to it, before `Logout` reaches MFA; ending a session is its
        // decision, and a session it keeps keeps its proofs.
    }

    /**
     * The factor's id, as a proof made with it names it: its identifier as
     * text, so a factor identified by a number is the one a proof naming that
     * number names.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return string
     */
    public static function factorReference(Factor $factor): string
    {
        return SignInProofs::factorReference($factor);
    }

    /**
     * Whether the proof is the sign-in's own first factor: a first factor made
     * with the method, and on the kind of channel, the session recorded.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @param  \SineMacula\Laravel\Authentication\Proofs\RecordedProof  $firstFactor
     * @return bool
     */
    private static function isTheFirstFactor(Proof $proof, RecordedProof $firstFactor): bool
    {
        $channel = $proof->channel;

        return $proof->kind   === ProofKind::FIRST_FACTOR
            && $proof->method === $firstFactor->method
            && $channel !== null
            && $channel->kind->value === $firstFactor->channel->kind->value;
    }

    /**
     * The guard's current session, when it is the identity's, or `null` when
     * the guard holds none of the identity's.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Session
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private function session(MultiFactorAuthenticatable $identity, string $application): ?Session
    {
        return $this->sessions->held($identity, $application);
    }

    /**
     * The guard's current session, when it is the sign-in the binding names and
     * is held by the identity the binding names; refused otherwise.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Authentication\Contracts\Session
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException
     */
    private function signInOf(ProofBinding $binding): Session
    {
        $identity = $this->signedIn($binding->application);

        try {

            if ($identity === null || !IdentityReference::of($identity)->owns($binding)) {
                throw new ProofRefusedException('The proof is bound to an identity the guard is not signed in as, so it cannot be recorded.');
            }

            return $this->sessions->of($identity, $binding->application, $binding->sessionId);
        } catch (SessionMismatchException|UnresolvedReferenceException $exception) {
            throw new ProofRefusedException('The proof is not bound to its identity\'s current sign-in, so it cannot be recorded.', previous: $exception);
        }
    }

    /**
     * The identity the application's guard is signed in as, when the
     * application is a declared guard and the identity can hold factors.
     *
     * @param  string  $application
     * @return ?\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    private function signedIn(string $application): ?MultiFactorAuthenticatable
    {
        $identity = is_array($this->config->get('auth.guards.' . $application)) ? Auth::guard($application)->user() : null;

        return $identity instanceof MultiFactorAuthenticatable ? $identity : null;
    }
}
