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
use SineMacula\Laravel\Iam\Mfa\Translation\SignIn;
use SineMacula\Laravel\Mfa\Attempts\ChallengeOutcome;
use SineMacula\Laravel\Mfa\Codes\SendResult;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;

/**
 * MFA's challenge gateway, sending and checking SMS and email codes through
 * `Auth::codes()`.
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

    /** @var string The detail of a check refused for a binding that is not the caller's own. */
    public const string NOT_THE_CALLERS = 'The binding does not name the identity the caller is.';

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
     * @throws \Throwable
     */
    #[\Override]
    public function send(CallerContext $caller, Factor $factor, ProofBinding $binding): SendResult
    {
        $owner = self::owner($factor, $binding);

        if ($owner === null || !$this->isTheCallers($caller, $binding, self::actionOf($binding, PendingAction::SEND_CODE, PendingAction::START_BOOTSTRAP_ENROLLMENT))) {
            return SendResult::refused(FailureReason::NOT_FOUND);
        }

        $codes = $this->service($binding->application);
        $kind  = self::kind($factor);

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
     * @throws \Throwable
     */
    #[\Override]
    public function verify(CallerContext $caller, Factor $factor, ProofBinding $binding, string $challengeId, #[\SensitiveParameter] string $code): ChallengeOutcome
    {
        $owner = self::owner($factor, $binding);

        if ($owner === null || !$this->isTheCallers($caller, $binding, self::actionOf($binding, PendingAction::VERIFY, PendingAction::CONFIRM_BOOTSTRAP_ENROLLMENT))) {
            return ChallengeOutcome::refused(FailureReason::NOT_FOUND, $owner === null ? self::NOT_FOUND : self::NOT_THE_CALLERS);
        }

        $codes = $this->service($binding->application);
        $kind  = self::kind($factor);

        if ($kind === null || $binding->purpose === Purpose::REAUTHENTICATE) {
            return ChallengeOutcome::refused(FailureReason::NOT_ACCEPTED, $kind === null ? self::NOT_A_CODE_CHANNEL : self::REAUTHENTICATION);
        }

        $bound = $this->bound($caller, $owner, $factor, $kind, $binding);

        return $this->codes->outcome($codes->verifyFactorCode($bound, $challengeId, $code, ClientTranslator::toAuthentication($caller->client)));
    }

    /**
     * Whether the binding is the caller's own: its identity, application and
     * sign-in, by a pending caller only for an action its session allows.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  \SineMacula\Laravel\Mfa\Enums\PendingAction  $action
     * @return bool
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private function isTheCallers(CallerContext $caller, ProofBinding $binding, PendingAction $action): bool
    {
        $identity = $caller->identity;

        if ($identity === null || $caller->application !== $binding->application || $caller->pending?->allows($action) === false) {
            return false;
        }

        $held    = $caller->pending === null ? $this->sessions->held($identity, $caller->application) : null;
        $session = $caller->pending->sessionId ?? ($held === null ? null : SignIn::reference($held, $caller->application));
        $owner   = ProofOwner::of($identity);

        return $session !== null && (new ProofBinding($owner->type, $owner->key, $binding->application, $session, $binding->purpose))->toArray() === $binding->toArray();
    }

    /**
     * The pending action a send or check needs: the bootstrap enrolment's for
     * an enrolment binding.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  \SineMacula\Laravel\Mfa\Enums\PendingAction  $action
     * @param  \SineMacula\Laravel\Mfa\Enums\PendingAction  $enrolling
     * @return \SineMacula\Laravel\Mfa\Enums\PendingAction
     */
    private static function actionOf(ProofBinding $binding, PendingAction $action, PendingAction $enrolling): PendingAction
    {
        return $binding->purpose === Purpose::ENROLLMENT ? $enrolling : $action;
    }

    /**
     * The factor's owner, when it is the binding's identity.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return ?\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private static function owner(Factor $factor, ProofBinding $binding): ?MultiFactorAuthenticatable
    {
        $owner = $factor instanceof EloquentFactor ? $factor->authenticatable()->getResults() : null;

        return $owner instanceof MultiFactorAuthenticatable && ProofOwner::of($owner)->owns($binding) ? $owner : null;
    }

    /**
     * The factor's channel kind, when it is SMS or email.
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
     * The factor code binding, with the caller kept for the counters.
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
