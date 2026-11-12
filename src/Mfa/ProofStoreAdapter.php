<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Requirements\RequirementSubject;
use SineMacula\Laravel\Iam\Exceptions\SessionMismatchException;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\Translation\SignIn;
use SineMacula\Laravel\Iam\Transactions\CrossMemberTransaction;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;

/**
 * MFA's proof store over `laravel-authentication`'s session proofs, where a
 * sign-in is the guard's current session (IAM-3.11).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ProofStoreAdapter implements ProofStore
{
    /** @var string Why a proof other than the sign-in's first factor is refused. */
    private const string RECORDED_ELSEWHERE = 'Only laravel-authentication records a session\'s proofs; a further proof reaches it through a step-up or a pending completion,'
        . ' or, in a test, through InteractsWithIam::actingOnVerifiedSession().';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Mfa\CurrentSession  $sessions
     * @param  \SineMacula\Laravel\Iam\Mfa\SignInProofs  $proofs
     * @param  \SineMacula\Laravel\Iam\Transactions\CrossMemberTransaction  $transaction
     */
    public function __construct(

        /** Resolves the sign-in MFA names to the guard's current session. */
        private CurrentSession $sessions,

        /** Reads the session's proofs as MFA's proofs of the sign-in. */
        private SignInProofs $proofs,

        /** Locks the session's row for the liveness check. */
        private CrossMemberTransaction $transaction,
    ) {}

    /**
     * Begin the identity's sign-in on the application.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $sessionId
     * @return void
     */
    #[\Override]
    public function begin(MultiFactorAuthenticatable $identity, string $application, string $sessionId): void
    {
        // laravel-authentication began the session, which is the sign-in.
    }

    /**
     * The guard's current session key, or `null` if it is not the identity's.
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
        $session = $this->sessions->held($identity, $application);

        return $session === null ? null : SignIn::reference($session, $application);
    }

    /**
     * Keep the live sign-in's own first factor, under the session's row lock,
     * and refuse any other proof.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException
     * @throws \Throwable
     */
    #[\Override]
    public function record(MultiFactorAuthenticatable $identity, Proof $proof): void
    {
        $this->transaction->run(function () use ($identity, $proof): void {

            $session     = $this->signInOf($identity, $proof->binding);
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
     * The sign-in's newest `RequirementSubject::MAX_LIMIT` proofs, oldest
     * first, or none unless it is the current sign-in.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $sessionId
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \Throwable
     */
    #[\Override]
    public function proofs(MultiFactorAuthenticatable $identity, string $application, string $sessionId): array
    {
        $session = $this->sessions->held($identity, $application);

        if ($session === null || SignIn::reference($session, $application) !== $sessionId) {
            return [];
        }

        $recorded = Auth::sessions($application)->proofs($session, limit: RequirementSubject::MAX_LIMIT);

        return $this->proofs->of($identity, $application, $session, array_reverse($recorded));
    }

    /**
     * The current sign-in's first factor, or `null` when there is no live
     * session or MFA cannot express it.
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
        $session = $this->sessions->held($identity, $application);

        if ($session === null) {
            return null;
        }

        $recorded = Auth::sessions($application)->firstFactor($session);

        return $recorded === null ? null : ($this->proofs->of($identity, $application, $session, [$recorded])[0] ?? null);
    }

    /**
     * Forget the factor's proofs.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $factorId
     * @return void
     */
    #[\Override]
    public function forgetFactor(MultiFactorAuthenticatable $identity, string $factorId): void
    {
        // MFA has deleted the factor, and the session revoker voids its proofs.
    }

    /**
     * Forget the identity's sign-in on the application.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return void
     */
    #[\Override]
    public function forget(MultiFactorAuthenticatable $identity, string $application): void
    {
        // laravel-authentication ends the session before `Logout` reaches MFA.
    }

    /**
     * Whether the proof is a first factor made with the method and kind of
     * channel the session recorded.
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
     * The identity's current session, when it is the sign-in its binding names.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Authentication\Contracts\Session
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private function signInOf(MultiFactorAuthenticatable $identity, ProofBinding $binding): Session
    {
        try {

            if (!ProofOwner::of($identity)->owns($binding)) {
                throw new ProofRefusedException('The proof is bound to another identity, so it cannot be recorded.');
            }

            return $this->sessions->of($identity, $binding->application, $binding->sessionId);
        } catch (SessionMismatchException|UnresolvedReferenceException $exception) {
            throw new ProofRefusedException('The proof is not bound to its identity\'s current sign-in, so it cannot be recorded.', previous: $exception);
        }
    }
}
