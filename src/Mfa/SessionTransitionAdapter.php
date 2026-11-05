<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use SineMacula\Laravel\Authentication\Sessions\FactorChangeResult;
use SineMacula\Laravel\Iam\Mfa\Translation\ChangeTranslator;
use SineMacula\Laravel\Mfa\Contracts\SessionTransition;
use SineMacula\Laravel\Mfa\Requirements\SessionChange;

/**
 * MFA's session transition, judging the guard's current session again through
 * `laravel-authentication` after a factor change on it, so a session that stops
 * meeting its requirement returns to pending (IAM-3.8).
 *
 * MFA calls it after every enrolment confirmation and passkey factor
 * registration on an active session, shortfall or not, and after a removal its
 * revoker did not judge, which this package's always does (IAM-3.7). The
 * session judged is the guard's current one, when it is the identity's and the
 * sign-in the change was made on (`CurrentSession`); when it is another, or
 * there is none, the change is refused by throwing (IAM-8.2), so it rolls back
 * rather than being committed unjudged.
 *
 * `laravel-authentication` judges it by its own rules, against the requirement
 * it resolves for the identity (IAM-3.1), never MFA's `outstanding` assessment:
 * kept active, returned to pending with a new pending credential, revoked, or
 * skipped when it is no longer live and active. Its result is MFA's completion,
 * which reaches the caller in the change's result once the change commits. The
 * change made crosses by its value, which both members spell the same.
 *
 * Stateless: the guard and its session are read on every call (IAM-8.1).
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
     */
    public function __construct(

        /** Resolves the sign-in the change was made on to the guard's session, and the guard's session service. */
        private CurrentSession $sessions,

        /** Translates MFA's change made to `laravel-authentication`'s. */
        private ChangeTranslator $changes,
    ) {}

    /**
     * Judge the session the change was made on again, returning
     * `laravel-authentication`'s factor change result as MFA's completion.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\SessionChange  $change
     * @return \SineMacula\Laravel\Authentication\Sessions\FactorChangeResult
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\SessionMismatchException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \Throwable
     */
    #[\Override]
    public function factorChanged(SessionChange $change): FactorChangeResult
    {
        $owner   = $this->sessions->identity($change->identity);
        $current = $this->sessions->of($change->identity, $change->application, $change->session);

        return $this->sessions
            ->sessions($change->application)
            ->factorChanged($owner, $this->changes->factorChangeMade($change->change), $current);
    }
}
