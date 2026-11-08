<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Testing;

use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Iam\Mfa\PendingCompletionAdapter;
use SineMacula\Laravel\Iam\Mfa\PendingSessionResolverAdapter;
use SineMacula\Laravel\Iam\Mfa\Translation\ClientTranslator;
use SineMacula\Laravel\Iam\Mfa\Translation\IdentityReference;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Context\SessionFirstFactor;
use SineMacula\Laravel\Mfa\Contracts\RequirementCheck;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;

/**
 * Completes, for `CallerSignIn`, a caller's sign-in that
 * `laravel-authentication` left pending on a further factor, as a person
 * completes it by verifying one of their factors, so a person who already holds
 * a confirmed factor, under an application that then requires one at sign-in,
 * can be acted as: a person seeded with a factor, and a person `$verified`
 * enrolled one for before.
 *
 * The further proof is the level's evidence (`LevelEvidence`; an authenticator
 * app, AAL2, when no level is asked for), made now with a confirmed factor of
 * its type the person holds, or with one enrolled for them when they hold none
 * (`FixtureFactors`), bound to the pending session for sign-in. It reaches
 * `laravel-authentication` as MFA's verification reaches it: through this
 * package's pending completion, for the pending context this package resolves
 * from the pending credential, with the caller's client, inside the sign-in's
 * transaction, flagged multifactor exactly when MFA's requirement check,
 * judging the pending session's first factor and this proof alone, dates the
 * multifactor evidence to this proof. A refusal is thrown as MFA's
 * `OperationRefusedException`, so the sign-in rolls back with it.
 *
 * A sign-in that signed in, failed, or waits first on a choice of principal is
 * handed back as it is, for `CallerSignIn` to judge.
 *
 * Stateless: the pending session is read on every call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CallerCompletion
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Mfa\PendingSessionResolverAdapter  $pendings
     * @param  \SineMacula\Laravel\Iam\Mfa\PendingCompletionAdapter  $completion
     * @param  \SineMacula\Laravel\Iam\Testing\FixtureFactors  $factors
     * @param  \SineMacula\Laravel\Mfa\Context\SessionFirstFactor  $proofs
     * @param  \SineMacula\Laravel\Mfa\Contracts\RequirementCheck  $check
     */
    public function __construct(

        /** Resolves MFA's pending context from the pending credential. */
        private PendingSessionResolverAdapter $pendings,

        /** Satisfies the pending session through `laravel-authentication`. */
        private PendingCompletionAdapter $completion,

        /** The factor of the evidence's type the person holds, or one enrolled for them. */
        private FixtureFactors $factors,

        /** Reads the pending session's first factor as MFA reads it. */
        private SessionFirstFactor $proofs,

        /** Evaluates the proofs as MFA evaluates them. */
        private RequirementCheck $check,
    ) {}

    /**
     * Complete the sign-in on the guard when it waits first on a further
     * factor, with a proof of the level's evidence (AAL2's when none is given),
     * from the client, and return the result; any other result is returned as
     * it is.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInResult  $result
     * @param  string  $guard
     * @param  ?\SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $level
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \Throwable
     */
    public function complete(SignInResult $result, string $guard, ?AssuranceLevel $level, ClientContext $client): SignInResult
    {
        $credential = $result->credential;

        if ($result->pending?->requires[0] !== PendingRequirement::MFA || $credential === null) {
            return $result;
        }

        $pending  = $this->pending($guard, $this->pendings->fromCredential($guard, $credential->reveal()));
        $evidence = LevelEvidence::of($level ?? AssuranceLevel::AAL2);
        $identity = $pending->identity;
        $proof    = $evidence->proof($this->factors->held($identity, $pending->application, $evidence->type), self::binding($pending), VerificationGeneration::current($identity));
        $judged   = $this->check->check(Requirement::none(), ...array_filter([$this->proofs->ofPending($identity, $pending), $proof]));

        return $this->completion->complete(CallerContext::forPending($pending, ClientTranslator::toMfa($client)), VerificationResult::verified(
            $proof,
            $judged,
            $evidence->amr,
            $evidence->type,
            $judged->multifactorAt?->equalTo($proof->provedAt) ?? false,
        ));
    }

    /**
     * The pending context read back from the credential, refusing a credential
     * that names no live pending session of the guard.
     *
     * @param  string  $guard
     * @param  ?\SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @return \SineMacula\Laravel\Mfa\Context\PendingContext
     *
     * @throws \LogicException
     */
    private function pending(string $guard, ?PendingContext $pending): PendingContext
    {
        return $pending ?? throw new \LogicException(sprintf('The pending sign-in on guard [%s] could not be read back.', $guard));
    }

    /**
     * What a proof completing the pending session is bound to: its identity,
     * its application and its key, for sign-in.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private static function binding(PendingContext $pending): ProofBinding
    {
        $owner = IdentityReference::of($pending->identity);

        return new ProofBinding($owner->type, $owner->key, $pending->application, $pending->sessionId, Purpose::SIGN_IN);
    }
}
