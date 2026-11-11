<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use Illuminate\Contracts\Auth\Factory as AuthFactory;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Codes\CodeService;
use SineMacula\Laravel\Authentication\Codes\FactorCodeBinding;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\Translation\ClientTranslator;
use SineMacula\Laravel\Iam\Mfa\Translation\CodeTranslator;
use SineMacula\Laravel\Iam\Mfa\Translation\IdentityReference;
use SineMacula\Laravel\Mfa\Attempts\ChallengeOutcome;
use SineMacula\Laravel\Mfa\Codes\SendResult;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;

/**
 * MFA's challenge gateway, sending and checking SMS and email factor codes
 * through `Auth::codes()` (IAM-3.9).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ChallengeGatewayAdapter implements ChallengeGateway
{
    /** @var string The detail of a check refused for a factor that is not the binding's identity's. */
    public const string NOT_FOUND = 'The factor is not one of the binding\'s identity\'s stored factors.';

    /** @var string The detail of a send or check refused for a binding of another application than the caller's. */
    public const string ANOTHER_APPLICATION = 'The binding names another application than the caller\'s.';

    /** @var string The detail of a check refused for a reauthentication. */
    public const string REAUTHENTICATION = 'A reauthentication proves the first factor, so no factor code answers one.';

    /** @var string The detail of a check refused for a factor whose driver delivers neither by SMS nor by email. */
    public const string NOT_A_CODE_CHANNEL = 'Factor codes go by SMS or email only.';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Auth\Factory  $auth
     * @param  \SineMacula\Laravel\Iam\Mfa\CurrentSession  $sessions
     * @param  \SineMacula\Laravel\Iam\Mfa\Translation\CodeTranslator  $codes
     * @param  \SineMacula\Laravel\Iam\Mfa\FactorCodeCallers  $callers
     */
    public function __construct(

        /** Resolves `laravel-authentication`'s code service for the guard. */
        private AuthFactory $auth,

        /** Resolves the guard, and the identity as `laravel-authentication`'s. */
        private CurrentSession $sessions,

        /** Translates the binding, the code request and the check. */
        private CodeTranslator $codes,

        /** Keeps the caller beside each binding, for the factor code counters. */
        private FactorCodeCallers $callers,
    ) {}

    /**
     * Send a code for the factor through `laravel-authentication`.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Codes\SendResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \Throwable
     */
    #[\Override]
    public function send(CallerContext $caller, Factor $factor, ProofBinding $binding): SendResult
    {
        self::assertIsTheCallersApplication($caller, $binding);

        $codes = $this->service($binding->application);
        $owner = self::owner($factor, $binding);
        $kind  = self::kind($factor);

        if ($owner === null) {
            return SendResult::refused(FailureReason::NOT_FOUND);
        }

        if ($kind === null || $binding->purpose === Purpose::REAUTHENTICATE) {
            return SendResult::refused(FailureReason::NOT_ACCEPTED);
        }

        $bound = $this->bound($caller, $owner, $factor, $kind, $binding);

        return $this->codes->sendResult($codes->sendFactorCode($bound, ClientTranslator::toAuthentication($caller->client)));
    }

    /**
     * Check the code against the challenge through `laravel-authentication`.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  string  $challengeId
     * @param  string  $code
     * @return \SineMacula\Laravel\Mfa\Attempts\ChallengeOutcome
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \Throwable
     */
    #[\Override]
    public function verify(CallerContext $caller, Factor $factor, ProofBinding $binding, string $challengeId, #[\SensitiveParameter] string $code): ChallengeOutcome
    {
        self::assertIsTheCallersApplication($caller, $binding);

        $codes = $this->service($binding->application);
        $owner = self::owner($factor, $binding);
        $kind  = self::kind($factor);

        if ($owner === null) {
            return ChallengeOutcome::refused(FailureReason::NOT_FOUND, self::NOT_FOUND);
        }

        if ($kind === null || $binding->purpose === Purpose::REAUTHENTICATE) {
            return ChallengeOutcome::refused(FailureReason::NOT_ACCEPTED, $kind === null ? self::NOT_A_CODE_CHANNEL : self::REAUTHENTICATION);
        }

        $bound = $this->bound($caller, $owner, $factor, $kind, $binding);

        return $this->codes->outcome($codes->verifyFactorCode($bound, $challengeId, $code, ClientTranslator::toAuthentication($caller->client)));
    }

    /**
     * Refuse a binding of another application than the caller's.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private static function assertIsTheCallersApplication(CallerContext $caller, ProofBinding $binding): void
    {
        if ($caller->application !== $binding->application) {
            throw new OperationRefusedException(FailureReason::NOT_ACCEPTED, self::ANOTHER_APPLICATION);
        }
    }

    /**
     * The factor's owner, when the factor is stored and owned by the binding's
     * identity.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return ?\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private static function owner(Factor $factor, ProofBinding $binding): ?MultiFactorAuthenticatable
    {
        $owner = $factor instanceof EloquentFactor ? $factor->authenticatable()->getResults() : null;

        return $owner instanceof MultiFactorAuthenticatable && IdentityReference::of($owner)->owns($binding) ? $owner : null;
    }

    /**
     * The channel kind the factor's driver delivers on, when it is SMS or
     * email.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return ?\SineMacula\Laravel\Mfa\Enums\ChannelKind
     */
    private static function kind(Factor $factor): ?ChannelKind
    {
        $kind = Mfa::driver($factor->getType())->channelKind();

        return $kind === ChannelKind::SMS || $kind === ChannelKind::EMAIL ? $kind : null;
    }

    /**
     * The factor code binding for the factor, with the caller kept beside it
     * for the counters.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $owner
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Enums\ChannelKind  $kind
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private function bound(CallerContext $caller, MultiFactorAuthenticatable $owner, Factor $factor, ChannelKind $kind, ProofBinding $binding): FactorCodeBinding
    {
        return $this->callers->hold($this->codes->toAuthentication($this->sessions->identity($owner), $factor, $kind, $binding), $caller);
    }

    /**
     * `laravel-authentication`'s code service for the application's guard.
     *
     * @param  string  $application
     * @return \SineMacula\Laravel\Authentication\Codes\CodeService
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private function service(string $application): CodeService
    {
        $auth = $this->auth;

        if (!$auth instanceof AuthManager) {
            throw UnresolvedReferenceException::forGuard($application);
        }

        $this->sessions->guard($application);

        return $auth->codes($application);
    }
}
