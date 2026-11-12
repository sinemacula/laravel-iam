<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use SineMacula\Laravel\Authentication\Sessions\FactorChangeResult;
use SineMacula\Laravel\Iam\Authorization\DecisionCacheInvalidation;
use SineMacula\Laravel\Iam\Mfa\Translation\ChangeTranslator;
use SineMacula\Laravel\Mfa\Contracts\SessionTransition;
use SineMacula\Laravel\Mfa\Requirements\SessionChange;

/**
 * MFA's session transition: `laravel-authentication` judges the changed session
 * again by its own rules.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SessionTransitionAdapter implements SessionTransition
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Mfa\CurrentSession  $sessions
     * @param  \SineMacula\Laravel\Iam\Mfa\Translation\ChangeTranslator  $changes
     * @param  \SineMacula\Laravel\Iam\Authorization\DecisionCacheInvalidation  $decisions
     */
    public function __construct(

        /** Resolves the sign-in the change was made on to its session, and the guard's session service. */
        private CurrentSession $sessions,

        /** Translates MFA's change made to `laravel-authentication`'s. */
        private ChangeTranslator $changes,

        /** Forgets the decisions that read the identity's authentication. */
        private DecisionCacheInvalidation $decisions,
    ) {}

    /**
     * Judge the changed session again and forget the decisions it read.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\SessionChange  $change
     * @return \SineMacula\Laravel\Authentication\Sessions\FactorChangeResult
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \Throwable
     */
    #[\Override]
    public function factorChanged(SessionChange $change): FactorChangeResult
    {
        $owner   = $this->sessions->identity($change->identity);
        $current = $this->sessions->named($change->identity, $change->application, $change->session);

        $result = $this->sessions
            ->sessions($change->application)
            ->factorChanged($owner, $this->changes->factorChangeMade($change->change), $current);

        $this->decisions->authenticationChanged($change->identity, $change->session);

        return $result;
    }
}
