<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Contracts\FreshnessPolicy;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Iam\Mfa\Translation\RequirementTranslator;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Enums\Operation;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * MFA's freshness gate, asking `laravel-authentication`'s freshness policy
 * about the caller's session (IAM-3.5).
 *
 * MFA hands it the caller, whose application is the guard of the same name,
 * which must be one of `laravel-authentication`'s guards, and whose session is
 * that guard's current session, held by the caller's identity: never the
 * default guard's, nor a session of whoever else the guard serves. Only an
 * active caller's session can be fresh, as MFA's own gate has it: a pending
 * caller has no session to judge yet, and nobody has none. The policy judges
 * each part MFA asks for on the newest of the session's proofs that meets it
 * within the part's maximum age, each made stricter by the application's own
 * setting for the operation in `laravel-authentication` (the shorter age, the
 * kinds both take, either's flags), and the session is fresh while every part
 * is met: until the earliest second one of them stops being met. With no part
 * asked for, the policy's own setting for the operation alone decides. Each
 * part is the requirement the stored proofs show:
 *
 * - an additional verification is a further factor or a recovery code;
 * - multifactor authentication is a proof whose evaluation reported it;
 * - phishing resistance is a proof observed to resist phishing.
 *
 * A minimum assurance level is not something `laravel-authentication`'s proofs
 * record, so a requirement asking for one is refused with an
 * `InvalidArgumentException`, as is a part with no maximum age or one longer
 * than a day: the gate is never asked a question it would have to guess the
 * answer to. A name that is not an operation's is answered first, never fresh
 * and with no requirement, whatever the caller asks; the caller's requirement
 * is then checked before anything is read. A caller whose guard holds no
 * session of its identity is not fresh, as MFA's contract has it; an
 * application that is not one of `laravel-authentication`'s guards cannot be
 * resolved and throws (IAM-8.2).
 *
 * `requirement()` answers the stricter of the caller's requirement and the
 * parts of the caller's application's setting MFA can express: a setting that
 * takes only further factors and recovery codes is an additional verification,
 * and its flags are multifactor authentication and phishing resistance, each
 * within its age. A setting that also takes a first factor has no MFA part, so
 * it adds nothing there, and with no caller's requirement there is none to
 * judge by.
 *
 * The parts cross through `RequirementTranslator`, which the factor-change
 * gate's requirement crosses through too.
 *
 * The policy reads the session again on the write connection and judges its
 * liveness itself, read as the call site needs it
 * (`CurrentSession::isInTransaction()`). Outside a transaction on the session
 * model's connection (MFA's route gate, `Mfa::isFresh()`) nothing acts on the
 * answer atomically, so `isFresh()` and `freshUntil()` ask plainly, read only,
 * and take no lock. Inside one (MFA's own factor-change gate, asking inside
 * MFA's transaction after its locks, which acts on the answer and takes a
 * grant's end from `freshUntil()`) they ask current: the policy locks the
 * session's row until the transaction ends and reads its proofs as committed,
 * so a step-up voided before the call never counts and one recorded before it
 * does, whatever the transaction read first. The session's row is then taken
 * after MFA's locks, as every adapter takes it, and its proofs after the row; a
 * removal through MFA's own gate goes on to lock the identity's other sessions'
 * rows after both, in the revoker's `factorRemoved()`, which is
 * `laravel-authentication`'s order. `requirement()` reads no proof, and asks
 * nothing current. It holds nothing between calls (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FreshnessGateAdapter implements FreshnessGate
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\FreshnessPolicy  $freshness
     * @param  \SineMacula\Laravel\Iam\Mfa\CurrentSession  $sessions
     * @param  \SineMacula\Laravel\Iam\Mfa\Translation\RequirementTranslator  $requirements
     */
    public function __construct(

        /** Judges the session's freshness. */
        private FreshnessPolicy $freshness,

        /** Resolves the caller's guard and its session. */
        private CurrentSession $sessions,

        /** Translates the caller's requirement and the application's setting. */
        private RequirementTranslator $requirements,
    ) {}

    /**
     * Whether the caller's session is fresh for the operation.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
     * @return bool
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    #[\Override]
    public function isFresh(CallerContext $caller, string $operation, ?Requirement $callerRequirement = null): bool
    {
        return $this->freshUntil($caller, $operation, $callerRequirement) !== null;
    }

    /**
     * The freshness the operation requires on the caller's application, or
     * `null` when it requires none.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
     * @return ?\SineMacula\Laravel\Mfa\Requirements\Requirement
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    #[\Override]
    public function requirement(CallerContext $caller, string $operation, ?Requirement $callerRequirement = null): ?Requirement
    {
        if (!Operation::isName($operation)) {
            return null;
        }

        // Translating the caller's parts refuses any the policy cannot hold the
        // session to.
        $asked = $this->parts($callerRequirement) === [null] ? null : $callerRequirement;

        $application = $caller->application;

        $this->sessions->guard($application);

        $setting = $this->freshness->requirement($application, $operation);
        $own     = $setting === null ? null : $this->requirements->fromFreshness($setting);

        return match (true) {
            $own   === null => $asked,
            $asked === null => $own,
            default         => Requirement::strictest($own, $asked),
        };
    }

    /**
     * Until when the caller's session stays fresh for the operation, or `null`
     * when it is not fresh.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
     * @return ?\Carbon\CarbonImmutable
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    #[\Override]
    public function freshUntil(CallerContext $caller, string $operation, ?Requirement $callerRequirement = null): ?CarbonImmutable
    {
        if (!Operation::isName($operation)) {
            return null;
        }

        $parts   = $this->parts($callerRequirement);
        $session = $this->session($caller);

        return $session === null ? null : $this->heldUntil($session, $operation, $parts, $this->sessions->isInTransaction());
    }

    /**
     * The active caller's session: its guard's current session, when it is the
     * caller's identity's; `null` for a pending caller, nobody, and a guard
     * holding no session of the identity's. An application that is no guard of
     * `laravel-authentication`'s throws.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Session
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private function session(CallerContext $caller): ?Session
    {
        $identity    = $caller->identity;
        $application = $caller->application;

        $this->sessions->guard($application);

        return $identity === null || $caller->pending !== null ? null : $this->sessions->held($identity, $application);
    }

    /**
     * `laravel-authentication`'s requirement for each part of the caller's, or
     * a single `null` (the policy's own setting alone) when the caller asks for
     * nothing.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @return list<?\SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement>
     *
     * @throws \InvalidArgumentException
     */
    private function parts(?Requirement $requirement): array
    {
        if ($requirement === null || $requirement->isEmpty()) {
            return [null];
        }

        return $this->requirements->toFreshnessParts($requirement);
    }

    /**
     * The first second the session stops meeting one of the parts, each judged
     * by the policy for the operation, current when asked inside a transaction
     * on the session model's connection and plainly otherwise, or `null` when
     * one is not met now.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  string  $operation
     * @param  list<?\SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement>  $parts
     * @param  bool  $current
     * @return ?\Carbon\CarbonImmutable
     */
    private function heldUntil(Session $session, string $operation, array $parts, bool $current): ?CarbonImmutable
    {
        $until = null;

        foreach ($parts as $part) {

            $held = $this->freshness->freshUntil($session, $operation, $part, current: $current);

            if ($held === null) {
                return null;
            }

            $until = $until === null || $held->lessThan($until) ? $held : $until;
        }

        return $until;
    }
}
