<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use Illuminate\Database\ConnectionResolverInterface;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Iam\Authorization\DecisionCacheInvalidation;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\Translation\ClientTranslator;
use SineMacula\Laravel\Iam\Mfa\Translation\ProofTranslator;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\PendingCompletion;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;

/**
 * MFA's pending completion, satisfying the pending session as the last write of
 * MFA's transaction.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PendingCompletionAdapter implements PendingCompletion
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Database\ConnectionResolverInterface  $database
     * @param  \SineMacula\Laravel\Iam\Mfa\CurrentSession  $sessions
     * @param  \SineMacula\Laravel\Iam\Mfa\Translation\ProofTranslator  $proofs
     * @param  \SineMacula\Laravel\Iam\Authorization\DecisionCacheInvalidation  $decisions
     */
    public function __construct(

        /** The connections the storage connection's transaction is read from. */
        private ConnectionResolverInterface $database,

        /** Resolves the guard's session service. */
        private CurrentSession $sessions,

        /** Translates the verified proof. */
        private ProofTranslator $proofs,

        /** Forgets the decisions that read the identity's authentication. */
        private DecisionCacheInvalidation $decisions,
    ) {}

    /**
     * Satisfy the caller's pending sign-in and forget the decisions it read.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Verification\VerificationResult  $result
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    #[\Override]
    public function complete(CallerContext $caller, VerificationResult $result): SignInResult
    {
        $pending = $caller->pending ?? throw new OperationRefusedException(FailureReason::NOT_ACCEPTED, 'The caller holds no pending session.');
        $proof   = $result->proof   ?? throw new OperationRefusedException(FailureReason::NOT_ACCEPTED, 'A failed verification proves nothing.');

        OperationRefusedException::unless(self::isForThePendingSession($pending, $proof), FailureReason::NOT_ACCEPTED, 'The proof is not bound to the pending session.');

        $identity = $pending->identity;

        if (!$identity instanceof Identity) {
            throw UnresolvedReferenceException::forIdentity($identity::class);
        }

        if ($this->database->connection(StorageConnection::name())->transactionLevel() === 0) {
            throw new \LogicException('A pending session is satisfied only as the last write of a transaction on the storage connection.');
        }

        $application = $pending->application;
        $proven      = $this->proofs->toResult($result, $identity);
        $outcome     = $this->sessions->sessions($application)->satisfy(self::credential($pending), $proven, ClientTranslator::toAuthentication($caller->client));

        $refusal = sprintf('laravel-authentication refused the proof as [%s].', $outcome->reason?->value);

        OperationRefusedException::unless(!$outcome->isFailed(), FailureReason::NOT_ACCEPTED, $refusal);

        $this->decisions->authenticationChanged($identity, $pending->sessionId);

        return $outcome;
    }

    /**
     * The pending credential the context keeps.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @return string
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private static function credential(PendingContext $pending): string
    {
        $application = $pending->application;
        $message     = 'The pending context keeps no pending credential for the guard [%s], so the pending session the proof was made for cannot be satisfied.';

        return $pending->credential() ?? throw new UnresolvedReferenceException(sprintf($message, $application), ReferenceKind::SESSION, $application);
    }

    /**
     * Whether the proof is bound to the pending session for a purpose it takes.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return bool
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private static function isForThePendingSession(PendingContext $pending, Proof $proof): bool
    {
        $binding = $proof->binding;
        $owner   = ProofOwner::of($pending->identity);

        return in_array($binding->purpose, [Purpose::SIGN_IN, Purpose::ENROLLMENT], true)
            && $owner->owns($binding)
            && $binding->application === $pending->application
            && $binding->sessionId   === $pending->sessionId;
    }
}
