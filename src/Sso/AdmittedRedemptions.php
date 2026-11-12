<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * The one redemption SSO admitted in this request, which the link contract, the
 * evidence policy and the exemption gate answer from.
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

    /** @var ?\SineMacula\Laravel\Sso\Http\ClientContext The client SSO was handed for the admitted redemption. */
    private ?ClientContext $client = null;

    /**
     * Record the redemption SSO admitted, with the client it was handed.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\RedemptionResult  $redemption
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return void
     *
     * @throws \LogicException
     */
    public function record(RedemptionResult $redemption, ClientContext $client): void
    {
        if (!$redemption->isAdmitted() || $redemption->result === null || $redemption->linkedIdentity === null || $redemption->linkId === null) {
            throw new \LogicException('Only a redemption SSO admitted, with the identity and the link it resolved, is recorded.');
        }

        if ($this->admitted !== null) {
            throw new \LogicException('One redemption is admitted at a time: another was recorded while one was held.');
        }

        $this->admitted = $redemption;
        $this->client   = $client;
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
     * The admitted redemption's client, for its identity and session alone.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $sessionId
     * @return ?\SineMacula\Laravel\Sso\Http\ClientContext
     */
    public function clientFor(IdentityReference $identity, ?string $sessionId): ?ClientContext
    {
        $admitted = $this->admitted;

        return $admitted?->linkedIdentity?->is($identity) === true && $admitted->sessionId === $sessionId ? $this->client : null;
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
