<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;

/**
 * The redemption SSO admitted in this request, which `laravel-authentication`'s
 * external identity links contract answers from (IAM-4.3, AUTH-3.9, SSO-8.3).
 *
 * A sign-in or a re-authentication records the redemption SSO admitted inside
 * its transaction (`record()`), and only then hands `laravel-authentication`
 * the result built from it; `laravel-authentication` asks its link contract for
 * the result's connection, issuer and subject inside that call, and the
 * contract answers the link this redemption resolved when the three are exactly
 * the admitted result's (`matching()`), and nothing otherwise. No link is ever
 * looked up again: a SAML link is keyed by the `NameID` format too, which the
 * contract is not handed, and a second lookup after SSO's locks could see
 * another link.
 *
 * Only an admitted redemption, with the identity and the link it resolved, is
 * recorded, and one at a time: recording another while one is held is a
 * `LogicException`, since one redemption never runs inside another. It is bound
 * scoped, under this package's own key for scoped adapters, so it holds one
 * request's or one job's redemption alone, and the worker reset forgets it
 * (IAM-8.1); each redemption also forgets it as its attempt starts and ends
 * (`forget()`), so a retried attempt, or a later call in the same request,
 * never answers from an admission that was rolled back.
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
     * Record the redemption SSO admitted, with the identity and the link it
     * resolved.
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
     * The redemption admitted in this request when its result's connection,
     * issuer and subject are exactly those given, compared byte for byte, or
     * `null` otherwise.
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
     * Forget the redemption admitted, if any.
     *
     * @return void
     */
    public function forget(): void
    {
        $this->admitted = null;
    }
}
