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
 * `laravel-authentication` (IAM-3.9): MFA's factor and proof binding become the
 * factor code binding `laravel-authentication` issues and checks a code under,
 * and back; MFA's admission and counted attempt become the factor code
 * admission `laravel-authentication` asks for; and `laravel-authentication`'s
 * code request and check become MFA's send result and challenge outcome.
 *
 * A factor code binding names MFA's factor by its id, the channel by the kind
 * the factor's driver states and the factor's own destination, and, for an
 * enrolment, a grant: MFA's grant is a secret it never hands out, and an
 * enrolment always makes a new pending factor, so the pending factor's id is
 * the grant, and MFA's counters judge the live enrolment itself under its lock.
 *
 * Both members spell the factor code refusals the same, so a refusal crosses by
 * value. MFA's refusals `laravel-authentication` has no word for (a pending
 * factor, an expired enrolment) cross as `not_found`, the factor named being
 * none MFA will challenge, and come back as that. A lockout crosses as a lock,
 * until when MFA says.
 *
 * `laravel-authentication` tells a wrong code apart from a challenge it did not
 * check one against. A wrong code, which it counted and reported, is MFA's
 * counted `invalid_code` failure, as is a malformed code, which it refuses as
 * `invalid` before checking any challenge: what MFA does with a counted failure
 * (keeping the IP address's slot, committing what the check did) is the safe
 * answer for both, while a refusal would let a wrong code's count roll back. A
 * challenge that is malformed, unknown, replaced or another binding's is
 * refused as `not_found`, and the binding's own challenge once it is used up,
 * by its code or by being ended, as `replayed`: neither counts against the
 * factor, and `laravel-authentication` reports neither (MFA's enrolment
 * confirmation counts a `replayed` against the enrolment, as it would not an
 * `expired`). It does not say whether the code checked at a used challenge is
 * the one that used it, so any well-formed code at one is `replayed`, never the
 * `expired` MFA's own codes answer a different code at a used challenge with.
 * An expired or exhausted challenge, which counts nothing, is refused as
 * `expired`, as MFA's own codes answer it; a lock, or the IP address's limit,
 * as `locked`, the limit until its window ends; and a send refused for the
 * cooldown, a full delivery window or the limits on code requests as
 * `sending_capped`, with how long to wait.
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
     * The factor code binding `laravel-authentication` issues and checks the
     * factor's codes under: the identity, the binding's application, sign-in
     * and purpose, the factor's id, its channel, and for an enrolment the
     * pending factor's id as the grant.
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
     * The channel the factor's codes go through, in `laravel-authentication`'s
     * terms: the kind its driver states, naming its destination.
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
     * The factor's id as a proof or a factor code binding names it, or `''`
     * when it is neither a string nor an integer.
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
     * `laravel-authentication`'s admission for MFA's: admitted, locked until
     * the lockout ends, or refused for MFA's reason.
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
     * `laravel-authentication`'s answer to an attempt MFA counted: admitted
     * when MFA passed it, or when it counted a wrong code that locked nothing;
     * locked when a lockout refused it, or when counting the wrong code locked
     * or disabled the factor or locked the identity
     * (`AttemptOutcome::$caused`), until the lockout ends, or with no time for
     * a factor disabled or an identity held at the failure ceiling; refused
     * when the factor is no longer the identity's, or MFA did not pass a code
     * that matched.
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
     * MFA's send result for a code `laravel-authentication` sent, which always
     * names its challenge for a factor's code.
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
     * `laravel-authentication`'s refusal for MFA's reason: the same value, or
     * `not_found` for a reason it has no word for.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @return \SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeRefusal
     */
    private static function refusal(?FailureReason $reason): FactorCodeRefusal
    {
        return FactorCodeRefusal::tryFrom($reason->value ?? '') ?? FactorCodeRefusal::NOT_FOUND;
    }

    /**
     * MFA's reason for `laravel-authentication`'s refusal: the same value, or
     * `not_found` when none was given.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeRefusal  $refusal
     * @return \SineMacula\Laravel\Mfa\Enums\FailureReason
     */
    private static function reason(?FactorCodeRefusal $refusal): FailureReason
    {
        return FailureReason::tryFrom($refusal->value ?? '') ?? FailureReason::NOT_FOUND;
    }

    /**
     * The seconds until the time given, or `null` when there is none.
     *
     * @param  ?\Carbon\CarbonImmutable  $until
     * @return ?int
     */
    private static function secondsUntil(?CarbonImmutable $until): ?int
    {
        return $until === null ? null : $until->getTimestamp() - CarbonImmutable::now()->getTimestamp();
    }

    /**
     * The time the seconds given from now end at, or `null` when there are
     * none.
     *
     * @param  ?int  $seconds
     * @return ?\Carbon\CarbonImmutable
     */
    private static function after(?int $seconds): ?CarbonImmutable
    {
        return $seconds === null ? null : CarbonImmutable::now()->addSeconds($seconds);
    }
}
