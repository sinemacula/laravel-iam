<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeRefusal;
use SineMacula\Laravel\Authentication\Codes\FactorCodeAdmission;
use SineMacula\Laravel\Authentication\Codes\FactorCodeBinding;
use SineMacula\Laravel\Authentication\Contracts\FactorCodeCounters;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Mfa\Translation\ClientTranslator;
use SineMacula\Laravel\Iam\Mfa\Translation\CodeTranslator;
use SineMacula\Laravel\Mfa\Attempts\ChallengeCounters;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Facades\Mfa;

/**
 * `laravel-authentication`'s factor code counters, answered by MFA's challenge
 * counters.
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
     * Admit, lock out or refuse a send or check of the binding's code.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding  $binding
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Codes\FactorCodeAdmission
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \Throwable
     */
    #[\Override]
    public function admit(FactorCodeBinding $binding, ClientContext $client): FactorCodeAdmission
    {
        $identity = self::identity($binding);
        $bound    = $this->codes->toMfa($identity, $binding);
        $factor   = $this->factor($identity, $binding);

        return $factor === null
            ? FactorCodeAdmission::refused(FactorCodeRefusal::NOT_FOUND)
            : $this->codes->admission($this->counters->isUsable($this->caller($identity, $binding, $client), $factor, $bound));
    }

    /**
     * Count one attempt and answer whether a matching code is accepted.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding  $binding
     * @param  string  $challengeId
     * @param  bool  $passed
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Codes\FactorCodeAdmission
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \Throwable
     */
    #[\Override]
    public function report(FactorCodeBinding $binding, string $challengeId, bool $passed, ClientContext $client): FactorCodeAdmission
    {
        $identity = self::identity($binding);
        $bound    = $this->codes->toMfa($identity, $binding);
        $factor   = $this->factor($identity, $binding);

        return $factor === null
            ? FactorCodeAdmission::refused(FactorCodeRefusal::NOT_FOUND)
            : $this->codes->attempt($this->counters->report($this->caller($identity, $binding, $client), $factor, $bound, $passed), $passed);
    }

    /**
     * The caller kept for the binding, or the binding's identity on the client.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding  $binding
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Mfa\Context\CallerContext
     *
     * @throws \InvalidArgumentException
     */
    private function caller(MultiFactorAuthenticatable $identity, FactorCodeBinding $binding, ClientContext $client): CallerContext
    {
        return $this->callers->of($binding) ?? CallerContext::forIdentity($identity, $binding->binding->application, ClientTranslator::toMfa($client));
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
     * The binding's factor on its own channel, matched by id in PHP, not SQL.
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

        if ($factor === null) {
            return null;
        }

        $channel = $this->codes->channel($factor, Mfa::driver($factor->getType())->channelKind());

        return $channel->kind === $binding->channel->kind && $channel->reference === $binding->channel->reference ? $factor : null;
    }
}
