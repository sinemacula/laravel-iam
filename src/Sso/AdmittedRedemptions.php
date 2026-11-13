<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * The one redemption SSO admitted in this request, which the link contract and
 * the evidence policy answer from.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AdmittedRedemptions
{
    /** @var ?\SineMacula\Laravel\Sso\Handoffs\RedemptionResult The redemption admitted in this request, while its transaction runs. */
    private ?RedemptionResult $admitted = null;

    /**
     * Record the redemption SSO admitted.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\RedemptionResult  $redemption
     * @return void
     *
     * @throws \LogicException
     */
    public function record(RedemptionResult $redemption): void
    {
        if (!$redemption->isAdmitted() || $redemption->result === null || $redemption->linkedIdentity === null || $redemption->linkId === null) {
            throw new \LogicException('Only a redemption SSO admitted, with the identity and the link it resolved, is recorded.');
        }

        if ($this->admitted !== null) {
            throw new \LogicException('One redemption is admitted at a time: another was recorded while one was held.');
        }

        $this->admitted = $redemption;
    }

    /**
     * The admitted redemption for exactly this connection, issuer and subject.
     *
     * @param  string  $connectionId
     * @param  string  $issuer
     * @param  string  $subject
     * @return ?\SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     */
    public function matching(string $connectionId, string $issuer, string $subject): ?RedemptionResult
    {
        $result = $this->admitted?->result;

        return $result !== null && $result->connectionId === $connectionId && $result->issuer === $issuer && $result->subject === $subject
            ? $this->admitted
            : null;
    }

    /**
     * The evidence SSO accepted for the identity through the connection.
     *
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return ?\SineMacula\Laravel\Sso\Evidence\AcceptedEvidence
     */
    public function acceptedEvidence(string $connectionId, IdentityReference $identity): ?AcceptedEvidence
    {
        $admitted = $this->admitted;

        return $admitted?->result?->connectionId === $connectionId && $admitted->linkedIdentity?->is($identity) === true ? $admitted->evidence : null;
    }

    /**
     * Forget the admitted redemption.
     *
     * @return void
     */
    public function forget(): void
    {
        $this->admitted = null;
    }
}
