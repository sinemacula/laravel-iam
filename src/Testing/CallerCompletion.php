<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Testing;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Iam\Mfa\PendingCompletionAdapter;
use SineMacula\Laravel\Iam\Mfa\PendingSessionResolverAdapter;
use SineMacula\Laravel\Iam\Mfa\Translation\ClientTranslator;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\RequirementCheck;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Testing\LevelEvidence;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;

/**
 * Completes a sign-in `laravel-authentication` left pending on a further
 * factor, with MFA's level evidence, as a person completes it.
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
     * @param  \SineMacula\Laravel\Mfa\Contracts\RequirementCheck  $check
     */
    public function __construct(

        /** Resolves MFA's pending context from the pending credential. */
        private PendingSessionResolverAdapter $pendings,

        /** Satisfies the pending session through `laravel-authentication`. */
        private PendingCompletionAdapter $completion,

        /** The real factor the further proof names. */
        private FixtureFactors $factors,

        /** Evaluates the proofs as MFA evaluates them. */
        private RequirementCheck $check,
    ) {}

    /**
     * Complete a sign-in waiting on a further factor, at AAL2 by default.
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
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     * @throws \Throwable
     */
    public function complete(SignInResult $result, string $guard, ?AssuranceLevel $level, ClientContext $client): SignInResult
    {
        $credential = $result->credential;

        if ($result->pending?->requires[0] !== PendingRequirement::MFA || $credential === null) {
            return $result;
        }

        $pending  = $this->pending($guard, $credential);
        $identity = $pending->identity;
        $owner    = ProofOwner::of($identity);
        $binding  = new ProofBinding($owner->type, $owner->key, $pending->application, $pending->sessionId, Purpose::SIGN_IN);
        $level ??= AssuranceLevel::AAL2;
        $factor = $this->factors->held($identity, $pending->application, $level);

        return $this->satisfy($pending, LevelEvidence::furtherProof($level, CarbonImmutable::now(), $binding, VerificationGeneration::current($identity), $factor), $client);
    }

    /**
     * Satisfy the pending session with the proof, from the client.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    public function satisfy(PendingContext $pending, Proof $proof, ClientContext $client): SignInResult
    {
        $judged = $this->check->check(Requirement::none(), $pending->firstFactor, $proof);

        return $this->completion->complete(CallerContext::forPending($pending, ClientTranslator::toMfa($client)), VerificationResult::verified(
            $proof,
            $judged,
            VerifiedSession::AMR[$proof->method] ?? [],
            $proof->method,
            $judged->multifactorAt?->equalTo($proof->provedAt) ?? false,
        ));
    }

    /**
     * The pending session of the guard the credential names.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret  $credential
     * @return \SineMacula\Laravel\Mfa\Context\PendingContext
     *
     * @throws \LogicException
     */
    public function pending(string $guard, #[\SensitiveParameter] Secret $credential): PendingContext
    {
        return $this->pendings->fromCredential($guard, $credential->reveal())
            ?? throw new \LogicException(sprintf('The pending sign-in on guard [%s] could not be read back.', $guard));
    }
}
