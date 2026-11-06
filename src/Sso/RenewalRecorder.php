<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * The one renewal SSO's redemption of a `reauthenticate` code asked for in this
 * request, recorded and never written (IAM-4.2).
 *
 * SSO's reauthentication sessions contract is asked to renew the session from
 * inside SSO's admission, handed the identity, the session, the provider's time
 * and the evidence accepted, but not the result's issuer and subject, which
 * `laravel-authentication`'s external re-authentication needs to find the link.
 * So the adapter records the renewal here (`record()`), writing nothing, and
 * `ReauthenticationRedemption` takes it back once SSO's admission answers
 * (`take()`) and makes the one write. A second renewal recorded while one is
 * held is a `LogicException`: a renewal is written once, never twice. A renewal
 * still held when the redemption's transaction is about to commit is one that
 * was never written, and the redemption throws rather than commit it
 * (`isHolding()`).
 *
 * A renewal is recorded only while a redemption is open to write it: the
 * redemption opens the recorder as each attempt starts (`open()`) and closes it
 * as each ends (`close()`), forgetting any renewal held each time, so a retried
 * attempt never meets the renewal of one rolled back. A renewal SSO asks for
 * while the recorder is closed, as when a `reauthenticate` code is admitted
 * through SSO's `HandoffRedemption::admit()` rather than through
 * `Iam::reauthentications()`, is one no redemption would write, so it is a
 * `LogicException`, which rolls SSO's admission back and leaves the code
 * unspent, rather than let SSO report a renewal that never happened. The
 * recorder counts its openings, so a redemption run while another is still open
 * in the same container (as a test runs a racing request) leaves the other
 * open; a close with no opening left changes nothing.
 *
 * It is bound scoped, under this package's own key for scoped adapters, so it
 * holds one request's or one job's renewal alone, and the worker reset forgets
 * it (IAM-8.1).
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

    /** @var int How many redemptions' attempts have opened the recorder and not yet closed it. */
    private int $openings = 0;

    /**
     * Open the recorder for one attempt of a redemption that writes the renewal
     * it records, forgetting any renewal held.
     *
     * @return void
     */
    public function open(): void
    {
        $this->renewal = null;

        $this->openings++;
    }

    /**
     * Close the recorder as the redemption's attempt ends, forgetting any
     * renewal held.
     *
     * @return void
     */
    public function close(): void
    {
        $this->renewal  = null;
        $this->openings = max(0, $this->openings - 1);
    }

    /**
     * Record the renewal SSO asked for, writing nothing, while a redemption is
     * open to write it.
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
     * The renewal recorded, which is no longer held once taken, or `null` when
     * none was recorded.
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
