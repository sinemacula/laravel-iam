<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa\Translation;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\Authentication\Codes\CodeRequest;
use SineMacula\Laravel\Authentication\Codes\Enums\CodeRequestStatus;
use SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeOutcome;
use SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeRefusal;
use SineMacula\Laravel\Authentication\Codes\FactorCodeAdmission;
use SineMacula\Laravel\Authentication\Codes\FactorCodeBinding;
use SineMacula\Laravel\Authentication\Codes\FactorCodeCheck;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Proofs\Channel as AuthenticationChannel;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding as AuthenticationBinding;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Mfa\Assurance\Channel as MfaChannel;
use SineMacula\Laravel\Mfa\Attempts\AttemptOutcome;
use SineMacula\Laravel\Mfa\Attempts\ChallengeAdmission;
use SineMacula\Laravel\Mfa\Attempts\ChallengeOutcome;
use SineMacula\Laravel\Mfa\Codes\SendResult;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Enums\ChannelKind as MfaChannelKind;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose as MfaPurpose;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding as MfaBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;

/**
 * Translates a delivered factor's code challenges between MFA and
 * `laravel-authentication`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CodeTranslator
{
    /** @var string The detail of a check `laravel-authentication` answered `invalid`. */
    public const string INVALID = 'laravel-authentication did not accept the code: it is wrong or malformed.';

    /** @var string The detail of a check of a challenge `laravel-authentication` did not find for the binding. */
    public const string NOT_FOUND = 'laravel-authentication found no challenge of the binding\'s by that id.';

    /** @var string The detail of a check of the binding's challenge once it is used up. */
    public const string REPLAYED = 'laravel-authentication found the challenge already used up.';

    /** @var string The detail of a check of a challenge that has expired or used up its attempts. */
    public const string EXPIRED = 'laravel-authentication found the challenge expired, or out of attempts.';

    /** @var string The detail of a check refused by a lock MFA reported. */
    public const string LOCKED = 'MFA has the factor or the identity locked.';

    /** @var string The detail of a check refused by MFA's counters. */
    public const string REFUSED = 'MFA\'s challenge counters refused the challenge.';

    /** @var string The detail of a check refused by the IP address's limit on checking factor codes. */
    public const string RATE_LIMITED = 'laravel-authentication\'s limit on checking factor codes from the IP address is reached.';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Mfa\Translation\ProofTranslator  $proofs
     * @param  \SineMacula\Laravel\Iam\Mfa\Translation\ChannelTranslator  $channels
     */
    public function __construct(

        /** Translates the binding's purpose. */
        private ProofTranslator $proofs,

        /** Translates the factor's channel. */
        private ChannelTranslator $channels,
    ) {}

    /**
     * The factor code binding codes are issued and checked under.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Enums\ChannelKind  $kind
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding
     *
     * @throws \InvalidArgumentException
     */
    public function toAuthentication(Identity $identity, Factor $factor, MfaChannelKind $kind, MfaBinding $binding): FactorCodeBinding
    {
        $reference = self::reference($factor);
        $proof     = new AuthenticationBinding($identity, $binding->application, $binding->sessionId, $this->proofs->toAuthenticationPurpose($binding->purpose));

        // MFA never hands out its grant, so the pending factor id stands in.
        return new FactorCodeBinding($proof, $reference, $this->channel($factor, $kind), $binding->purpose === MfaPurpose::ENROLLMENT ? $reference : null);
    }

    /**
     * MFA's proof binding for the factor code binding.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @param  \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function toMfa(Authenticatable $identity, FactorCodeBinding $binding): MfaBinding
    {
        $owner       = ProofOwner::of($identity);
        $application = $binding->binding->application;
        $session     = $binding->binding->sessionId;

        if ((!is_string($session) && !is_int($session)) || $session === '') {
            throw UnresolvedReferenceException::forSession($application);
        }

        return new MfaBinding($owner->type, $owner->key, $application, (string) $session, $this->proofs->purpose($binding->binding->purpose));
    }

    /**
     * The factor's channel: its driver's kind, naming its destination.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Enums\ChannelKind  $kind
     * @return \SineMacula\Laravel\Authentication\Proofs\Channel
     *
     * @throws \InvalidArgumentException
     */
    public function channel(Factor $factor, MfaChannelKind $kind): AuthenticationChannel
    {
        return $this->channels->toAuthentication(new MfaChannel($kind, $factor->getDestination()));
    }

    /**
     * The factor's id as a string, or `''` when it is not scalar.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return string
     */
    public static function reference(Factor $factor): string
    {
        $id = $factor->getFactorIdentifier();

        return is_string($id) || is_int($id) ? (string) $id : '';
    }

    /**
     * `laravel-authentication`'s admission for MFA's.
     *
     * @param  \SineMacula\Laravel\Mfa\Attempts\ChallengeAdmission  $admission
     * @return \SineMacula\Laravel\Authentication\Codes\FactorCodeAdmission
     */
    public function admission(ChallengeAdmission $admission): FactorCodeAdmission
    {
        return match (true) {
            $admission->isAdmitted()                     => FactorCodeAdmission::admitted(),
            $admission->reason === FailureReason::LOCKED => FactorCodeAdmission::locked($admission->lockedUntil),
            default                                      => FactorCodeAdmission::refused(self::refusal($admission->reason)),
        };
    }

    /**
     * The admission for an attempt MFA counted.
     *
     * @param  \SineMacula\Laravel\Mfa\Attempts\AttemptOutcome  $outcome
     * @param  bool  $matched
     * @return \SineMacula\Laravel\Authentication\Codes\FactorCodeAdmission
     */
    public function attempt(AttemptOutcome $outcome, bool $matched): FactorCodeAdmission
    {
        return match (true) {
            $outcome->passed           => FactorCodeAdmission::admitted(),
            $outcome->lockout !== null => FactorCodeAdmission::locked($outcome->lockout->until),
            $outcome->caused  !== null => FactorCodeAdmission::locked($outcome->caused->until),
            !$outcome->found           => FactorCodeAdmission::refused(FactorCodeRefusal::NOT_FOUND),
            $matched                   => FactorCodeAdmission::refused(FactorCodeRefusal::NOT_ACCEPTED),
            default                    => FactorCodeAdmission::admitted(),
        };
    }

    /**
     * MFA's send result for `laravel-authentication`'s code request.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeRequest  $request
     * @return \SineMacula\Laravel\Mfa\Codes\SendResult
     *
     * @throws \LogicException
     */
    public function sendResult(CodeRequest $request): SendResult
    {
        return match ($request->status) {
            CodeRequestStatus::SENT                                                  => self::sent($request),
            CodeRequestStatus::RATE_LIMITED, CodeRequestStatus::DELIVERIES_EXHAUSTED => SendResult::refused(FailureReason::SENDING_CAPPED, $request->retryAfter),
            CodeRequestStatus::LOCKED                                                => SendResult::refused(FailureReason::LOCKED, self::secondsUntil($request->lockedUntil)),
            CodeRequestStatus::REFUSED                                               => SendResult::refused(self::reason($request->refusal)),
            default                                                                  => SendResult::refused(FailureReason::NOT_FOUND),
        };
    }

    /**
     * MFA's challenge outcome for `laravel-authentication`'s check.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\FactorCodeCheck  $check
     * @return \SineMacula\Laravel\Mfa\Attempts\ChallengeOutcome
     */
    public function outcome(FactorCodeCheck $check): ChallengeOutcome
    {
        return match ($check->outcome) {
            FactorCodeOutcome::VERIFIED                              => ChallengeOutcome::passed(),
            FactorCodeOutcome::INVALID                               => ChallengeOutcome::failed(FailureReason::INVALID_CODE, self::INVALID),
            FactorCodeOutcome::NOT_FOUND                             => ChallengeOutcome::refused(FailureReason::NOT_FOUND, self::NOT_FOUND),
            FactorCodeOutcome::USED                                  => ChallengeOutcome::refused(FailureReason::REPLAYED, self::REPLAYED),
            FactorCodeOutcome::EXPIRED, FactorCodeOutcome::EXHAUSTED => ChallengeOutcome::refused(FailureReason::EXPIRED, self::EXPIRED),
            FactorCodeOutcome::LOCKED                                => ChallengeOutcome::refused(FailureReason::LOCKED, self::LOCKED, $check->lockedUntil),
            FactorCodeOutcome::REFUSED                               => ChallengeOutcome::refused(self::reason($check->refusal), self::REFUSED),
            FactorCodeOutcome::RATE_LIMITED                          => ChallengeOutcome::refused(FailureReason::LOCKED, self::RATE_LIMITED, self::after($check->retryAfter)),
        };
    }

    /**
     * MFA's send result for a sent code, which always names its challenge.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeRequest  $request
     * @return \SineMacula\Laravel\Mfa\Codes\SendResult
     *
     * @throws \LogicException
     */
    private static function sent(CodeRequest $request): SendResult
    {
        $challenge = $request->challengeId;
        $expiresAt = $request->expiresAt;

        if ($challenge === null || $expiresAt === null) {
            throw new \LogicException('laravel-authentication answered a factor code as sent without naming its challenge.');
        }

        return SendResult::sent($challenge, $expiresAt);
    }

    /**
     * `laravel-authentication`'s refusal for MFA's reason, or `not_found`.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @return \SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeRefusal
     */
    private static function refusal(?FailureReason $reason): FactorCodeRefusal
    {
        return FactorCodeRefusal::tryFrom($reason->value ?? '') ?? FactorCodeRefusal::NOT_FOUND;
    }

    /**
     * MFA's reason for `laravel-authentication`'s refusal, or `not_found`.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeRefusal  $refusal
     * @return \SineMacula\Laravel\Mfa\Enums\FailureReason
     */
    private static function reason(?FactorCodeRefusal $refusal): FailureReason
    {
        return FailureReason::tryFrom($refusal->value ?? '') ?? FailureReason::NOT_FOUND;
    }

    /**
     * The seconds until the time, if any.
     *
     * @param  ?\Carbon\CarbonImmutable  $until
     * @return ?int
     */
    private static function secondsUntil(?CarbonImmutable $until): ?int
    {
        return $until === null ? null : $until->getTimestamp() - CarbonImmutable::now()->getTimestamp();
    }

    /**
     * The time the seconds from now end at, if any.
     *
     * @param  ?int  $seconds
     * @return ?\Carbon\CarbonImmutable
     */
    private static function after(?int $seconds): ?CarbonImmutable
    {
        return $seconds === null ? null : CarbonImmutable::now()->addSeconds($seconds);
    }
}
