<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use SineMacula\Laravel\Authentication\Sessions\AccessTokenResult;
use SineMacula\Laravel\Iam\Authorization\DecisionCacheInvalidation;
use SineMacula\Laravel\Iam\Mfa\Translation\ClientTranslator;
use SineMacula\Laravel\Iam\Mfa\Translation\ProofTranslator;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Contracts\StepUp;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;

/**
 * MFA's step-up, stepping `laravel-authentication`'s session up with the
 * verified proof bound to it for `step_up` (IAM-3.4).
 *
 * MFA hands it the caller, whose identity and application it acts for: never
 * the identity the guard serves, so the step-up is the caller's own. The caller
 * must be an active one (a pending caller's proof is the pending completion's,
 * and nobody has no session to step up), and the proof's binding must name the
 * caller's application, which is the guard of the same name, and the identity.
 * The session stepped up is the sign-in the binding names, never the guard's
 * current one, so a step-up made from a queued job, a console command or a
 * request another guard serves steps up the sign-in MFA named. The proof is
 * translated into the proof result `laravel-authentication` takes, bound to
 * that identity, guard and session for the purpose MFA verified it for,
 * accepted, and multifactor only when MFA says the proof itself refreshes the
 * multifactor evidence of the session's first factor
 * (`VerificationResult::$refreshesMultifactor`), never because of another proof
 * the session holds. It is handed to `stepUp()`, which locks the row of the
 * session the proof is bound to (after MFA's own locks, as the last write of
 * MFA's transaction), checks it is still one of the guard's live, active
 * sessions of a person, owned by the identity, records the proof and issues the
 * session a new access token, handed the caller's client (`ClientTranslator`)
 * as the client it was served to. The access token result is MFA's completion,
 * so it reaches the caller as `VerificationResult::$completion`. Once the token
 * is issued, the decisions `laravel-authorization` keeps for the request or job
 * are forgotten, naming the session stepped up and the caller
 * (`DecisionCacheInvalidation`, IAM-6.11): the verification passed changed the
 * proofs they read.
 *
 * MFA hands over only a proof it accepted after the session's first factor, so
 * nothing here judges the proof again. A failed result, a caller that is
 * pending or nobody, a proof bound to another application or to another
 * identity, and a proof `laravel-authentication` refuses (one made for another
 * purpose than `step_up`, a sign-in's included, or bound to a session that is
 * not one of the identity's live, active sessions on the guard) are refused
 * with an `OperationRefusedException` carrying `not_accepted`, as MFA's own
 * completion refuses them, so the code's use and the count roll back;
 * `laravel-authentication`'s reason is kept in the exception's detail. An
 * application that names no guard of `laravel-authentication`'s, and a caller
 * `laravel-authentication` does not sign in, cannot be resolved and throw
 * `UnresolvedReferenceException` (IAM-8.2), inside the same transaction.
 *
 * It holds nothing between calls (IAM-8.1).
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
     * @param  \SineMacula\Laravel\Iam\Mfa\Translation\ProofTranslator  $proofs
     * @param  \SineMacula\Laravel\Iam\Authorization\DecisionCacheInvalidation  $decisions
     */
    public function __construct(

        /** Resolves the guard's session service and the caller as `laravel-authentication`'s identity. */
        private CurrentSession $current,

        /** Translates the verified proof into `laravel-authentication`'s proof result. */
        private ProofTranslator $proofs,

        /** Forgets the decisions that read the caller's authentication. */
        private DecisionCacheInvalidation $decisions,
    ) {}

    /**
     * Step the caller's session up with the verified proof.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Verification\VerificationResult  $result
     * @return \SineMacula\Laravel\Authentication\Sessions\AccessTokenResult
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     * @throws \Throwable
     */
    #[\Override]
    public function stepUp(CallerContext $caller, VerificationResult $result): AccessTokenResult
    {
        $proof       = $result->proof ?? throw self::refused('A failed verification proves nothing.');
        $identity    = $caller->identity;
        $application = $caller->application;

        if ($identity === null || $caller->pending !== null || $proof->binding->application !== $application) {
            throw self::refused('Only an active caller\'s session is stepped up, with a proof made on its application.');
        }

        $sessions = $this->current->sessions($application);

        if (!ProofOwner::of($identity)->owns($proof->binding)) {
            throw self::refused('The proof is not bound to the caller.');
        }

        $proven = $this->proofs->toResult($result, $this->current->identity($identity));
        $token  = $sessions->stepUp($proven, ClientTranslator::toAuthentication($caller->client));

        if (!$token->isIssued()) {
            throw self::refused(sprintf('laravel-authentication refused the step-up: [%s].', $token->reason->value ?? ''));
        }

        $this->decisions->authenticationChanged($identity, $proof->binding->sessionId);

        return $token;
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
