<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use SineMacula\Laravel\Authentication\Sessions\AccessTokenResult;
use SineMacula\Laravel\Iam\Mfa\Translation\IdentityReference;
use SineMacula\Laravel\Iam\Mfa\Translation\ProofTranslator;
use SineMacula\Laravel\Iam\Mfa\Translation\SignIn;
use SineMacula\Laravel\Mfa\Contracts\StepUp;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;

/**
 * MFA's step-up, stepping `laravel-authentication`'s session up with the
 * verified proof bound to it for `step_up` (IAM-3.4).
 *
 * The proof's binding names the application, which is the guard of the same
 * name, and the sign-in, which must be that guard's current session, held by
 * the identity the proof names. The proof is translated into the proof result
 * `laravel-authentication` takes, bound to that identity, guard and session for
 * the purpose MFA verified it for, with MFA's evaluation of the proof on its
 * own after the session's first factor (`ProofEvaluator`), never of every proof
 * the session holds, so it is recorded multifactor only when it is the evidence
 * of a multifactor combination. It is handed to `stepUp()`, which locks the
 * session's row (after MFA's own locks, as the last write of MFA's
 * transaction), checks the session is still one of the guard's live, active
 * sessions of a person, records the proof and issues the session a new access
 * token. The access token result is MFA's completion, so it reaches the caller
 * as `VerificationResult::$completion`.
 *
 * A failed result, a proof bound to another identity or to another of the
 * identity's sessions, a session whose first factor is not known, a proof MFA
 * does not accept after it, and a proof `laravel-authentication` refuses (one
 * made for another purpose than `step_up`, a sign-in's included, or a session
 * no longer live) are refused with an `OperationRefusedException` carrying
 * `not_accepted`, as MFA's own completion refuses them, so the code's use and
 * the count roll back; `laravel-authentication`'s reason is kept in the
 * exception's detail. An application that names no guard of
 * `laravel-authentication`'s, and a guard holding no session of a person MFA
 * knows, cannot be resolved and throw `UnresolvedReferenceException` (IAM-8.2),
 * inside the same transaction.
 *
 * It holds nothing between calls: the guard and its session are read on every
 * call (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class StepUpAdapter implements StepUp
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Mfa\CurrentSession  $current
     * @param  \SineMacula\Laravel\Iam\Mfa\ProofStoreAdapter  $store
     * @param  \SineMacula\Laravel\Iam\Mfa\ProofEvaluator  $evaluator
     * @param  \SineMacula\Laravel\Iam\Mfa\Translation\ProofTranslator  $proofs
     */
    public function __construct(

        /** Resolves the guard, the identity it serves and its current session. */
        private CurrentSession $current,

        /** Reads the session's first factor. */
        private ProofStoreAdapter $store,

        /** Judges the proof on its own after the session's first factor. */
        private ProofEvaluator $evaluator,

        /** Translates the verified proof into `laravel-authentication`'s proof result. */
        private ProofTranslator $proofs,
    ) {}

    /**
     * Step the caller's session up with the verified proof, returning
     * `laravel-authentication`'s access token result as MFA's completion.
     *
     * @param  \SineMacula\Laravel\Mfa\Verification\VerificationResult  $result
     * @return \SineMacula\Laravel\Authentication\Sessions\AccessTokenResult
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \Throwable
     */
    #[\Override]
    public function stepUp(VerificationResult $result): AccessTokenResult
    {
        $proof       = $result->proof ?? throw self::refused('A failed verification proves nothing.');
        $application = $proof->binding->application;
        $identity    = $this->current->caller($application);
        $session     = $this->current->current($identity, $application);

        if (!self::isBoundTo($proof->binding, IdentityReference::of($identity), SignIn::reference($session, $application))) {
            throw self::refused('The proof is not bound to the caller\'s current session.');
        }

        $sessions   = $this->current->sessions($application);
        $evaluation = $this->evaluator->evaluate($this->store->firstFactorOf($identity, $application, $session), $proof);
        $token      = $sessions->stepUp($this->proofs->toResult($result, $identity, $evaluation));

        return $token->isIssued() ? $token : throw self::refused(sprintf('laravel-authentication refused the step-up: [%s].', $token->reason->value ?? ''));
    }

    /**
     * Whether the binding names the identity and the sign-in given.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  \SineMacula\Laravel\Iam\Mfa\Translation\IdentityReference  $identity
     * @param  string  $signIn
     * @return bool
     */
    private static function isBoundTo(ProofBinding $binding, IdentityReference $identity, string $signIn): bool
    {
        return $identity->owns($binding) && $binding->sessionId === $signIn;
    }

    /**
     * The refusal of a result the session cannot take, with the detail for the
     * logs.
     *
     * @param  string  $detail
     * @return \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private static function refused(string $detail): OperationRefusedException
    {
        return new OperationRefusedException(FailureReason::NOT_ACCEPTED, $detail);
    }
}
