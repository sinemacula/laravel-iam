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
 * MFA's step-up, recording the verified proof on the sign-in it is bound to.
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
     * The refusal of a result the session cannot take.
     *
     * @param  string  $detail
     * @return \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private static function refused(string $detail): OperationRefusedException
    {
        return new OperationRefusedException(FailureReason::NOT_ACCEPTED, $detail);
    }
}
