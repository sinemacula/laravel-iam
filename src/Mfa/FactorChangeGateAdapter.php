<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Factors\FactorChangeVerdict;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Requirements\RequirementSubject;
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
 * The sign-in the change is made from is the guard's current session, the one
 * the MFA application is named after (`CurrentSession`); another of the
 * identity's sessions, or none, is refused by throwing (IAM-8.2).
 * `laravel-authentication`'s gate then locks the session's row until MFA's
 * transaction ends, so it is taken last, confirms the session is still one of
 * the guard's live, active sessions and a person's, and judges its freshness
 * for the change: a first additional factor on a fresh reauthentication with
 * the first factor, every other change on a fresh step-up, never one made with
 * the factor a removal names. The requirement the application configures for
 * the change's operation in MFA is held to as well, the stricter applying.
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
 * The proof `laravel-authentication` allowed the change on is then read back
 * among the session's counting proofs, current: inside MFA's transaction the
 * session's row is locked and the proofs are read with a shared lock, so a
 * proof another transaction voided while the change waited no longer counts,
 * and the change is refused as `not_fresh`. `factorChange()` judges freshness
 * with a plain read, which a snapshot fixed before the wait (MySQL's at
 * REPEATABLE READ, when MFA's change runs inside a transaction someone else
 * opened, which is not supported) would answer from what was voided; the read
 * back keeps such a change from being made on it. A proof among more newer
 * proofs of its kind than one read returns is refused the same way, never
 * guessed to count.
 *
 * Every refusal `laravel-authentication` answers with, a session no longer
 * live, active and a person's included, is MFA's `not_fresh`: no step-up could
 * be fresh on a session that is not. MFA's own guard has refused a machine
 * identity before it asks. `laravel-authentication`'s reason is kept in the
 * refusal's detail, for logs. An allowed change lasts until the session stops
 * being fresh for it, which a grant takes its end from.
 *
 * Stateless: the guard and its session are read on every call (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FactorChangeGateAdapter implements FactorChangeGate
{
    /** @var string Why a change is refused whose fresh proof is not among the session's counting proofs read current. */
    private const string NOT_COUNTING = 'The proof laravel-authentication allowed the change on is not among the session\'s counting proofs read current,'
        . ' so it is not taken to count.';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Mfa\CurrentSession  $sessions
     * @param  \SineMacula\Laravel\Iam\Mfa\Translation\ChangeTranslator  $changes
     * @param  \SineMacula\Laravel\Iam\Mfa\Translation\RequirementTranslator  $requirements
     */
    public function __construct(

        /** Resolves the sign-in the change is made from to the guard's session, and the guard's session service. */
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
     * @return ?\Carbon\CarbonImmutable
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\SessionMismatchException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \Throwable
     */
    #[\Override]
    public function authorize(FactorChangeRequest $request): ?CarbonImmutable
    {
        $session     = $this->sessions->of($request->identity, $request->application, $request->session);
        $requirement = $request->requirement === null ? null : $this->requirements->toFreshness($request->requirement);

        $service = $this->sessions->sessions($request->application);
        $verdict = $service->factorChange($session, $this->changes->factorChange($request->change), $requirement, $request->factorId);
        $proof   = self::allowedOn($verdict, $request);

        $counting = $service->proofs($session, $proof->authenticatedAt, [$proof->kind], RequirementSubject::MAX_LIMIT);
        $current  = array_map(static fn (RecordedProof $counted): string => $counted->id, $counting);

        OperationRefusedException::unless(in_array($proof->id, $current, true), FailureReason::NOT_FRESH, self::NOT_COUNTING);

        return $verdict->freshUntil;
    }

    /**
     * The fresh proof `laravel-authentication` allowed the change on, which an
     * allowed verdict always carries and a refused one never does; the change
     * is refused, as MFA's `not_fresh`, when it was not allowed.
     *
     * @param  \SineMacula\Laravel\Authentication\Factors\FactorChangeVerdict  $verdict
     * @param  \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest  $request
     * @return \SineMacula\Laravel\Authentication\Proofs\RecordedProof
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private static function allowedOn(FactorChangeVerdict $verdict, FactorChangeRequest $request): RecordedProof
    {
        $proof = $verdict->proof;

        if ($proof !== null) {
            return $proof;
        }

        $detail = sprintf('laravel-authentication refused the change [%s] from the session: [%s].', $request->change->value, $verdict->reason->value ?? '');

        throw new OperationRefusedException(FailureReason::NOT_FRESH, $detail);
    }
}
