<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Http\Request;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\Translation\IdentityReference;
use SineMacula\Laravel\Iam\Mfa\Translation\ProofTranslator;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\PendingCompletion;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;

/**
 * MFA's pending completion, satisfying `laravel-authentication`'s pending
 * session as the last write of MFA's transaction, so the sign-in result never
 * reaches a response if MFA's commit fails (IAM-3.3).
 *
 * A failed result, and a proof bound to another identity, application or
 * sign-in than the pending session's, or made for a purpose a pending session
 * cannot take (a sign-in, or the enrolment of the additional factor that
 * confirms a bootstrap enrolment), are refused with an
 * `OperationRefusedException` as `not_accepted` before anything is read, so the
 * verification rolls back with them.
 *
 * Otherwise the proof crosses as `laravel-authentication`'s proof result, bound
 * to the pending session's key for the same purpose, with MFA's evaluation of
 * the proof on its own after the pending session's first factor
 * (`ProofEvaluator`), never of every proof the session holds, and is handed to
 * `Auth::sessions()->satisfy()` with the request's own pending credential, read
 * from the body field the resolver reads it from. A proof MFA does not accept
 * after that first factor is refused as `not_accepted`. It is called only
 * inside a transaction on the storage connection, where MFA calls it last:
 * `satisfy()` then stores the proof and activates the session in a savepoint of
 * MFA's transaction, and binds the guard only once that transaction commits, so
 * a rollback, or a commit that fails, leaves the session pending, the proof
 * unstored and the result unreturned. A refusal `laravel-authentication`
 * answers (the session no longer pending, the proof not one it takes, its
 * binding not the credential's session, a tenant requiring single sign-on) is
 * thrown as `not_accepted` too, naming its reason in the detail for logs; it
 * wrote nothing. A request without a pending credential, and an identity that
 * is not `laravel-authentication`'s, cannot be resolved and throw (IAM-8.2).
 *
 * What it returns is `laravel-authentication`'s `SignInResult`, signed in or
 * still pending, which reaches the caller as MFA's completion.
 *
 * Stateless: the request, the guard and the session are read on every call.
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
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Database\ConnectionResolverInterface  $database
     * @param  \SineMacula\Laravel\Iam\Mfa\PendingSessionResolverAdapter  $pending
     * @param  \SineMacula\Laravel\Iam\Mfa\CurrentSession  $sessions
     * @param  \SineMacula\Laravel\Iam\Mfa\ProofEvaluator  $evaluator
     * @param  \SineMacula\Laravel\Iam\Mfa\Translation\ProofTranslator  $proofs
     */
    public function __construct(

        /** The container the request is resolved from. */
        private Container $container,

        /** The connections the storage connection's transaction is read from. */
        private ConnectionResolverInterface $database,

        /** Reads the request's pending credential. */
        private PendingSessionResolverAdapter $pending,

        /** Resolves the guard's session service. */
        private CurrentSession $sessions,

        /** Judges the proof on its own after the pending session's first factor. */
        private ProofEvaluator $evaluator,

        /** Translates the verified proof. */
        private ProofTranslator $proofs,
    ) {}

    /**
     * Satisfy the pending sign-in with the verified proof, returning
     * `laravel-authentication`'s sign-in result as MFA's completion.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @param  \SineMacula\Laravel\Mfa\Verification\VerificationResult  $result
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    #[\Override]
    public function complete(PendingContext $pending, VerificationResult $result): SignInResult
    {
        $proof = $result->proof ?? throw new OperationRefusedException(FailureReason::NOT_ACCEPTED, 'A failed verification proves nothing.');

        OperationRefusedException::unless(self::isForThePendingSession($pending, $proof), FailureReason::NOT_ACCEPTED, 'The proof is not bound to the pending session.');

        $identity = $pending->identity;

        if (!$identity instanceof Identity) {
            throw UnresolvedReferenceException::forIdentity($identity::class);
        }

        if ($this->database->connection(StorageConnection::name())->transactionLevel() === 0) {
            throw new \LogicException('A pending session is satisfied only as the last write of a transaction on the storage connection.');
        }

        $application = $pending->application;
        $proven      = $this->proofs->toResult($result, $identity, $this->evaluator->evaluate($pending->firstFactor, $proof));
        $outcome     = $this->sessions->sessions($application)->satisfy($this->credential($application), $proven);

        $refusal = sprintf('laravel-authentication refused the proof as [%s].', $outcome->reason?->value);

        OperationRefusedException::unless(!$outcome->isFailed(), FailureReason::NOT_ACCEPTED, $refusal);

        return $outcome;
    }

    /**
     * The request's pending credential.
     *
     * @param  string  $application
     * @return string
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private function credential(string $application): string
    {
        $request = $this->container->bound('request') ? $this->container->make('request') : null;

        $credential = $request instanceof Request ? $this->pending->credential($request, $application) : null;

        if ($credential === null) {
            $message = 'The request carries no pending credential for the guard [%s], so the pending session the proof was made for cannot be satisfied.';

            throw new UnresolvedReferenceException(sprintf($message, $application), ReferenceKind::SESSION, $application);
        }

        return $credential;
    }

    /**
     * Whether the proof is bound to the pending session's identity, application
     * and sign-in, for a purpose a pending session can take: a sign-in, or the
     * enrolment of the additional factor that confirms a bootstrap enrolment
     * (MFA makes no other proof for an enrolment).
     *
     * @param  \SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return bool
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private static function isForThePendingSession(PendingContext $pending, Proof $proof): bool
    {
        $binding = $proof->binding;
        $owner   = IdentityReference::of($pending->identity);

        return in_array($binding->purpose, [Purpose::SIGN_IN, Purpose::ENROLLMENT], true)
            && $owner->owns($binding)
            && $binding->application === $pending->application
            && $binding->sessionId   === $pending->sessionId;
    }
}
