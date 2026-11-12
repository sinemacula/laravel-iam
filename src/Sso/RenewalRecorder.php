<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * Holds the renewal SSO asks for while admitting a `reauthenticate` code until
 * the redemption writes it, since SSO's call lacks the issuer and subject.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RenewalRecorder
{
    /** @var ?\SineMacula\Laravel\Iam\Sso\Renewal The renewal recorded and not yet taken. */
    private ?Renewal $renewal = null;

    /** @var int Open attempts, counted so a nested redemption leaves the outer one open. */
    private int $openings = 0;

    /**
     * Open the recorder for one attempt, forgetting any renewal held.
     *
     * @return void
     */
    public function open(): void
    {
        $this->renewal = null;

        $this->openings++;
    }

    /**
     * Close the recorder for one attempt, forgetting any renewal held.
     *
     * @return void
     */
    public function close(): void
    {
        $this->renewal  = null;
        $this->openings = max(0, $this->openings - 1);
    }

    /**
     * Record the renewal while a redemption is open to write it.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $sessionId
     * @param  \Carbon\CarbonImmutable  $authenticatedAt
     * @param  ?\SineMacula\Laravel\Sso\Evidence\AcceptedEvidence  $evidence
     * @return void
     *
     * @throws \LogicException
     */
    public function record(IdentityReference $identity, string $sessionId, CarbonImmutable $authenticatedAt, ?AcceptedEvidence $evidence): void
    {
        if ($this->openings === 0) {
            throw new \LogicException('SSO asked for a renewal no redemption would write: a re-authentication is redeemed through Iam::reauthentications().');
        }

        if ($this->renewal !== null) {
            throw new \LogicException('A re-authentication renews its session once: a second renewal was recorded in one redemption.');
        }

        $this->renewal = new Renewal($identity, $sessionId, $authenticatedAt, $evidence);
    }

    /**
     * Take the renewal recorded, if any.
     *
     * @return ?\SineMacula\Laravel\Iam\Sso\Renewal
     */
    public function take(): ?Renewal
    {
        $renewal       = $this->renewal;
        $this->renewal = null;

        return $renewal;
    }

    /**
     * Whether a renewal is recorded and not yet taken.
     *
     * @return bool
     */
    public function isHolding(): bool
    {
        return $this->renewal !== null;
    }
}
