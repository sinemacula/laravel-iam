<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Mfa;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Contracts\FreshnessPolicy;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Iam\Mfa\Translation\RequirementTranslator;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Enums\Operation;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * MFA's freshness gate, asking `laravel-authentication`'s freshness policy
 * about the caller's session (IAM-3.5).
 *
 * The caller's session is the current session of the default guard, which is
 * MFA's application and must be one of `laravel-authentication`'s guards. The
 * policy judges each part MFA asks for on the newest of the session's proofs
 * that meets it within the part's maximum age, each made stricter by the
 * application's own setting for the operation in `laravel-authentication` (the
 * shorter age, the kinds both take, either's flags), and the session is fresh
 * while every part is met: until the earliest second one of them stops being
 * met. With no part asked for, the policy's own setting for the operation alone
 * decides. Each part is the requirement the stored proofs show:
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
 * is then checked before anything is read. A request with no session is not
 * fresh, as MFA's contract has it; a default guard that is not one of
 * `laravel-authentication`'s cannot be resolved and throws (IAM-8.2).
 *
 * `requirement()` answers the stricter of the caller's requirement and the
 * parts of the application's setting MFA can express: a setting that takes only
 * further factors and recovery codes is an additional verification, and its
 * flags are multifactor authentication and phishing resistance, each within its
 * age. A setting that also takes a first factor has no MFA part, so it adds
 * nothing there, and with no caller's requirement there is none to judge by.
 *
 * The parts cross through `RequirementTranslator`, which the factor-change
 * gate's requirement crosses through too.
 *
 * Reads only, with no lock: the policy reads the session again on the write
 * connection and judges its liveness itself, and a caller that acts on the
 * answer atomically locks the session first. It holds nothing between calls
 * (IAM-8.1).
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

        /** Resolves the default guard. */
        private CurrentSession $sessions,

        /** Translates the caller's requirement and the application's setting. */
        private RequirementTranslator $requirements,
    ) {}

    /**
     * Whether the caller's session is fresh for the operation.
     *
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
     * @return bool
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    #[\Override]
    public function isFresh(string $operation, ?Requirement $callerRequirement = null): bool
    {
        return $this->freshUntil($operation, $callerRequirement) !== null;
    }

    /**
     * The freshness the operation requires, or `null` when it requires none.
     *
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
     * @return ?\SineMacula\Laravel\Mfa\Requirements\Requirement
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    #[\Override]
    public function requirement(string $operation, ?Requirement $callerRequirement = null): ?Requirement
    {
        if (!Operation::isName($operation)) {
            return null;
        }

        // Translating the caller's parts refuses any the policy cannot hold the
        // session to.
        $asked = $this->parts($callerRequirement) === [null] ? null : $callerRequirement;

        $application = $this->sessions->defaultGuard();

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
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
     * @return ?\Carbon\CarbonImmutable
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    #[\Override]
    public function freshUntil(string $operation, ?Requirement $callerRequirement = null): ?CarbonImmutable
    {
        if (!Operation::isName($operation)) {
            return null;
        }

        $parts   = $this->parts($callerRequirement);
        $session = $this->sessions->guard($this->sessions->defaultGuard())->session();

        return $session === null ? null : $this->heldUntil($session, $operation, $parts);
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
     * by the policy for the operation, or `null` when one is not met now.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  string  $operation
     * @param  list<?\SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement>  $parts
     * @return ?\Carbon\CarbonImmutable
     */
    private function heldUntil(Session $session, string $operation, array $parts): ?CarbonImmutable
    {
        $until = null;

        foreach ($parts as $part) {

            $held = $this->freshness->freshUntil($session, $operation, $part);

            if ($held === null) {
                return null;
            }

            $until = $until === null || $held->lessThan($until) ? $held : $until;
        }

        return $until;
    }
}
