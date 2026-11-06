<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Factors\FactorChangeVerdict;
use SineMacula\Laravel\Iam\Mfa\Translation\ChangeTranslator;
use SineMacula\Laravel\Iam\Mfa\Translation\RequirementTranslator;
use SineMacula\Laravel\Mfa\Contracts\FactorChangeGate;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest;

/**
 * MFA's factor-change gate, passing each factor change through
 * `laravel-authentication`'s inside MFA's transaction, after MFA's locks, in
 * place of MFA's own freshness check for those changes (IAM-3.6).
 *
 * The sign-in the change is made from is the session MFA names
 * (`FactorChangeRequest::$session`), read by its key on the guard the MFA
 * application is named after (`CurrentSession::named()`), whatever the guard
 * holds now; a sign-in that is no session of the identity's on that guard is
 * refused by throwing (IAM-8.2). `laravel-authentication`'s gate then locks the
 * session's row until MFA's transaction ends, after MFA's locks, confirms the
 * session is still one of the guard's live, active sessions and a person's, and
 * judges its freshness for the change: a first additional factor on a fresh
 * reauthentication with the first factor, every other change on a fresh
 * step-up, never one made with the factor a removal names. It judges that
 * freshness under the session's lock on the session's proofs as committed (it
 * asks its freshness policy current), so a step-up voided before the gate never
 * allows a change and one recorded before it does, whatever MFA's transaction,
 * or a transaction it runs inside, read first; the adapter takes that verdict
 * as it is, with no read of its own. A removal then goes on to lock the
 * identity's other sessions' rows, in the revoker's `factorRemoved()`, after
 * the session's row and its proofs: `laravel-authentication`'s order, under
 * which, on MySQL and MariaDB at REPEATABLE READ, a step-up or reauthentication
 * of a neighbouring session can deadlock with the removal, and the side the
 * database fails is retried by its caller. The requirement the application
 * configures for the change's operation in MFA is held to as well, the stricter
 * applying.
 *
 * That requirement crosses as `laravel-authentication`'s freshness requirement,
 * which holds what a stored proof can show and no more: the shortest of its
 * parts' maximum ages (a part with none, or one longer, is held to a day, the
 * longest that requirement takes), an additional verification as a further
 * factor or a recovery code, and multifactor and phishing resistance as the
 * flags of the same names. A minimum assurance level cannot cross, so a
 * requirement that asks for one is refused as a misconfiguration rather than
 * judged without it. The requirement crosses through `RequirementTranslator`,
 * as the freshness gate's does.
 *
 * Every refusal `laravel-authentication` answers with, a session no longer
 * live, active and a person's included, is MFA's `not_fresh`: no step-up could
 * be fresh on a session that is not. MFA's own guard has refused a machine
 * identity before it asks. `laravel-authentication`'s reason is kept in the
 * refusal's detail, for logs. An allowed change lasts until the session stops
 * being fresh for it, which a grant takes its end from.
 *
 * Stateless: the session is read on every call (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FactorChangeGateAdapter implements FactorChangeGate
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Mfa\CurrentSession  $sessions
     * @param  \SineMacula\Laravel\Iam\Mfa\Translation\ChangeTranslator  $changes
     * @param  \SineMacula\Laravel\Iam\Mfa\Translation\RequirementTranslator  $requirements
     */
    public function __construct(

        /** Resolves the sign-in the change is made from to its session, and the guard's session service. */
        private CurrentSession $sessions,

        /** Translates MFA's change to `laravel-authentication`'s. */
        private ChangeTranslator $changes,

        /** Translates the requirement MFA's application configures for the change. */
        private RequirementTranslator $requirements,
    ) {}

    /**
     * Allow the change, returning until when the session stays fresh for it, or
     * refuse it.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest  $request
     * @return \Carbon\CarbonImmutable
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \Throwable
     */
    #[\Override]
    public function authorize(FactorChangeRequest $request): CarbonImmutable
    {
        $session     = $this->sessions->named($request->identity, $request->application, $request->session);
        $requirement = $request->requirement === null ? null : $this->requirements->toFreshness($request->requirement);

        $service = $this->sessions->sessions($request->application);
        $verdict = $service->factorChange($session, $this->changes->factorChange($request->change), $requirement, $request->factorId);

        return self::allowedUntil($verdict, $request);
    }

    /**
     * Until when the session stays fresh for the change, which an allowed
     * verdict always carries and a refused one never does; the change is
     * refused, as MFA's `not_fresh`, when it was not allowed.
     *
     * @param  \SineMacula\Laravel\Authentication\Factors\FactorChangeVerdict  $verdict
     * @param  \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest  $request
     * @return \Carbon\CarbonImmutable
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private static function allowedUntil(FactorChangeVerdict $verdict, FactorChangeRequest $request): CarbonImmutable
    {
        $until = $verdict->freshUntil;

        if ($until !== null) {
            return $until;
        }

        $detail = sprintf('laravel-authentication refused the change [%s] from the session: [%s].', $request->change->value, $verdict->reason->value ?? '');

        throw new OperationRefusedException(FailureReason::NOT_FRESH, $detail);
    }
}
