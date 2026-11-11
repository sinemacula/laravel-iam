<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use SineMacula\Laravel\Authentication\Sessions\FactorChangeResult;
use SineMacula\Laravel\Iam\Authorization\DecisionCacheInvalidation;
use SineMacula\Laravel\Iam\Mfa\Translation\ChangeTranslator;
use SineMacula\Laravel\Mfa\Contracts\SessionTransition;
use SineMacula\Laravel\Mfa\Requirements\SessionChange;

/**
 * MFA's session transition, judging the session a factor change was made on
 * again through `laravel-authentication`, so a session that stops meeting its
 * requirement returns to pending (IAM-3.8).
 *
 * MFA calls it after every enrolment confirmation and passkey factor
 * registration on an active session, shortfall or not, and after a removal its
 * revoker did not judge, which this package's always does (IAM-3.7). The
 * session judged is the one MFA names (`SessionChange::$session`), read by its
 * key on the guard the change's application names (`CurrentSession::named()`),
 * whatever the guard holds now, so a change made from a queued job, a console
 * command or a request another guard serves judges the sign-in it was made on;
 * a sign-in that is no session of the identity's on that guard is refused by
 * throwing (IAM-8.2), so the change rolls back rather than being committed
 * unjudged.
 *
 * `laravel-authentication` judges it by its own rules, against the requirement
 * it resolves for the identity (IAM-3.1), never MFA's `outstanding` assessment:
 * kept active, returned to pending with a new pending credential, revoked, or
 * skipped when it is no longer live and active. Its result is MFA's completion,
 * which reaches the caller in the change's result once the change commits. The
 * change made crosses by its value, which both members spell the same. The
 * decisions `laravel-authorization` keeps for the request or job are then
 * forgotten, naming that sign-in and the identity (`DecisionCacheInvalidation`,
 * IAM-6.11): a confirmed factor or a registered passkey can change the
 * requirement the identity's sessions meet, and a session returned to pending
 * meets none.
 *
 * Stateless: the session is read on every call (IAM-8.1).
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
     * Judge the session the change was made on again, then forget the decisions
     * that read its authentication, returning `laravel-authentication`'s factor
     * change result as MFA's completion.
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
