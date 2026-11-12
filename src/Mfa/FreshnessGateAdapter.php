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
 * about the caller's session.
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
     * The stricter of the caller's requirement and the application's setting.
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

        // Translating refuses any part the policy cannot hold a session to.
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
     * Until when the caller's session stays fresh for the operation, if it is.
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
     * The active caller's session, if the guard holds the identity's.
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
     * A requirement per part, or `[null]` for the policy's setting alone.
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
     * When the session first stops meeting a part, or `null` if one is unmet.
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
