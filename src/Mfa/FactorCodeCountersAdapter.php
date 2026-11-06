<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeRefusal;
use SineMacula\Laravel\Authentication\Codes\FactorCodeAdmission;
use SineMacula\Laravel\Authentication\Codes\FactorCodeBinding;
use SineMacula\Laravel\Authentication\Contracts\FactorCodeCounters;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\Translation\CodeTranslator;
use SineMacula\Laravel\Mfa\Attempts\ChallengeCounters;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Facades\Mfa;

/**
 * `laravel-authentication`'s factor code counters, answered by MFA's challenge
 * counters (IAM-3.9).
 *
 * `admit()` asks `ChallengeCounters::isUsable()` for the factor and the binding
 * the factor code binding names, before `laravel-authentication` locks or
 * writes the challenge, and `report()` asks `ChallengeCounters::report()` once
 * for each attempt `laravel-authentication` counts, with whether the code
 * matched. Each is asked for the caller MFA handed the challenge gateway, kept
 * beside the binding (`FactorCodeCallers`), so a pending sign-in's first factor
 * and bootstrap enrolment, and the client an attempt is counted against, are
 * the caller's; a binding the gateway did not make is asked for as the
 * binding's identity on the binding's application, with no client known.
 * Nothing is read from a request, so whatever request the container holds, its
 * client and any pending credential it carries never reach a count. Both run
 * inside `laravel-authentication`'s transaction on the shared storage
 * connection, so the attempt and MFA's count commit, or roll back, as one.
 * `isUsable()` takes MFA's locks (the identity's state, then its factors)
 * and reads the session's first factor before the challenge's row is locked;
 * `report()` takes no lock those do not already cover. MFA's admission and
 * attempt outcome are translated into `laravel-authentication`'s factor code
 * admission: admitted, locked until a time, or refused for a reason (see
 * `Translation\CodeTranslator`). A wrong code whose count locked or disabled
 * the factor, or locked the identity, is answered as locked, until the lockout
 * MFA says it caused ends, so `laravel-authentication`'s check carries the lock
 * this attempt caused; one that locked nothing is answered as admitted. A
 * factor disabled, or an identity held, at the failure ceiling has no time to
 * end at, so its lock carries none.
 *
 * The factor is the identity's stored factor the binding names by id, read
 * unlocked and matched exactly: MFA reads it again under its lock. One that is
 * not the identity's, and a binding whose channel is not the factor's own kind
 * and destination, are refused as `not_found` without asking MFA, so no code
 * for a factor ever goes anywhere but to that factor. An identity that is not
 * one of MFA's, and a binding naming no session MFA could refer back to, cannot
 * be resolved and throw, inside the transaction (IAM-8.2), as MFA's counters
 * throw there for a caller kept as nobody. It holds nothing between calls
 * (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FactorCodeCountersAdapter implements FactorCodeCounters
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Mfa\Attempts\ChallengeCounters  $counters
     * @param  \SineMacula\Laravel\Iam\Mfa\Translation\CodeTranslator  $codes
     * @param  \SineMacula\Laravel\Iam\Mfa\FactorCodeCallers  $callers
     */
    public function __construct(

        /** MFA's per-factor and per-identity counts and lockouts. */
        private ChallengeCounters $counters,

        /** Translates the binding, the admission and the attempt. */
        private CodeTranslator $codes,

        /** The caller the challenge gateway kept beside the binding. */
        private FactorCodeCallers $callers,
    ) {}

    /**
     * Admit, lock out or refuse a delivery or a check of the binding's factor
     * code, as MFA's challenge counters judge the factor usable.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding  $binding
     * @return \SineMacula\Laravel\Authentication\Codes\FactorCodeAdmission
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \Throwable
     */
    #[\Override]
    public function admit(FactorCodeBinding $binding): FactorCodeAdmission
    {
        $identity = self::identity($binding);
        $bound    = $this->codes->toMfa($identity, $binding);
        $factor   = $this->factor($identity, $binding);

        return $factor === null
            ? FactorCodeAdmission::refused(FactorCodeRefusal::NOT_FOUND)
            : $this->codes->admission($this->counters->isUsable($this->caller($identity, $binding), $factor, $bound));
    }

    /**
     * Count one attempt at the challenge against the factor and the identity in
     * MFA's challenge counters, and answer whether a matching code is accepted.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding  $binding
     * @param  string  $challengeId
     * @param  bool  $passed
     * @return \SineMacula\Laravel\Authentication\Codes\FactorCodeAdmission
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \Throwable
     */
    #[\Override]
    public function report(FactorCodeBinding $binding, string $challengeId, bool $passed): FactorCodeAdmission
    {
        $identity = self::identity($binding);
        $bound    = $this->codes->toMfa($identity, $binding);
        $factor   = $this->factor($identity, $binding);

        return $factor === null
            ? FactorCodeAdmission::refused(FactorCodeRefusal::NOT_FOUND)
            : $this->codes->attempt($this->counters->report($this->caller($identity, $binding), $factor, $bound, $passed), $passed);
    }

    /**
     * The caller the challenge gateway kept beside the binding, or the
     * binding's identity on its application when the gateway made none.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Context\CallerContext
     *
     * @throws \InvalidArgumentException
     */
    private function caller(MultiFactorAuthenticatable $identity, FactorCodeBinding $binding): CallerContext
    {
        return $this->callers->of($binding) ?? CallerContext::forIdentity($identity, $binding->binding->application);
    }

    /**
     * The identity the binding names, which must be one MFA holds factors for.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private static function identity(FactorCodeBinding $binding): MultiFactorAuthenticatable
    {
        $identity = $binding->binding->identity;

        return $identity instanceof MultiFactorAuthenticatable ? $identity : throw UnresolvedReferenceException::forMfaIdentity($identity::class);
    }

    /**
     * The identity's stored factor the binding names, read unlocked from the
     * write connection and matched by id exactly, in PHP, as MFA matches one,
     * so a database's collation never lets one id find another; and only when
     * the binding's channel is its own.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding  $binding
     * @return ?\SineMacula\Laravel\Mfa\Contracts\Factor
     *
     * @throws \InvalidArgumentException
     */
    private function factor(MultiFactorAuthenticatable $identity, FactorCodeBinding $binding): ?Factor
    {
        $factor = $identity->authFactors()->useWritePdo()->get()->first(static fn (Factor $factor): bool => CodeTranslator::reference($factor) === $binding->factor);

        if (!$factor instanceof Factor) {
            return null;
        }

        $channel = $this->codes->channel($factor, Mfa::driver($factor->getType())->channelKind());

        return $channel->kind === $binding->channel->kind && $channel->reference === $binding->channel->reference ? $factor : null;
    }
}
