<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use SineMacula\Laravel\Authentication\Contracts\FreshnessPolicy;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement;
use SineMacula\Laravel\Iam\Mfa\CurrentSession;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Identities\Caller;

/**
 * SSO's freshness, judged by `laravel-authentication`'s freshness policy on the
 * caller's own session, with SSO's maximum age as the requirement.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FreshnessAdapter implements Freshness
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\FreshnessPolicy  $freshness
     * @param  \SineMacula\Laravel\Iam\Mfa\CurrentSession  $sessions
     * @param  \SineMacula\Laravel\Iam\Sso\IdentityReferences  $identities
     */
    public function __construct(

        /** Judges the session's freshness. */
        private FreshnessPolicy $freshness,

        /** Finds the caller's session among its identity's own. */
        private CurrentSession $sessions,

        /** Resolves the identity SSO names. */
        private IdentityReferences $identities,
    ) {}

    /**
     * Whether the caller's session is fresh within SSO's maximum age.
     *
     * @param  \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation  $operation
     * @param  int  $maxAgeSeconds
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    #[\Override]
    public function check(FreshnessOperation $operation, int $maxAgeSeconds, ?Caller $caller): FreshnessOutcome
    {
        $requirement = FreshnessRequirement::within($maxAgeSeconds);
        $session     = $this->session($caller);

        // SSO asks inside its transaction only once its own locks are held.
        return $session !== null && $this->freshness->freshProof($session, $operation->value, $requirement, current: $this->sessions->isInTransaction()) !== null
            ? FreshnessOutcome::FRESH
            : FreshnessOutcome::STALE;
    }

    /**
     * The session the caller names among its identity's own, if any.
     *
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Session
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    private function session(?Caller $caller): ?Session
    {
        if ($caller === null || $caller->sessionId === null) {
            return null;
        }

        return $this->sessions->owned($this->identities->identity($caller->identity), $caller->sessionId);
    }
}
