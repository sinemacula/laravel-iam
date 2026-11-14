<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use SineMacula\Laravel\Authentication\External\ExternalEvidence;
use SineMacula\Laravel\Authentication\External\ExternalResult;
use SineMacula\Laravel\Authentication\External\ProviderContext;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * Builds `laravel-authentication`'s external result from a redemption SSO
 * admitted, never from anything the client sent.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ExternalResults
{
    /**
     * The external result of an admitted sign-in.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\RedemptionResult  $redemption
     * @return \SineMacula\Laravel\Authentication\External\ExternalResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public static function from(RedemptionResult $redemption): ExternalResult
    {
        $result     = self::verified($redemption);
        $provenance = $redemption->provenance;

        return new ExternalResult(
            connectionId: $result->connectionId,
            issuer: $result->issuer,
            subject: $result->subject,
            tenantId: $result->tenantId,
            authenticatedAt: $result->authenticationContext->authenticatedAt,
            sessionNotAfter: $redemption->sessionNotAfter,
            policyVersion: $redemption->enforcementVersion,
            evidence: self::evidence($redemption->evidence),
            linkId: $redemption->linkId,
            requestReference: $result->requestReference->value,
            providerContext: $provenance === null ? null : new ProviderContext($provenance->toArray()),
            nameIdFormat: $result->nameIdFormat,
        );
    }

    /**
     * The external result of an admitted re-authentication.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\RedemptionResult  $redemption
     * @param  \SineMacula\Laravel\Iam\Sso\Renewal  $renewal
     * @return \SineMacula\Laravel\Authentication\External\ExternalResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public static function renewing(RedemptionResult $redemption, Renewal $renewal): ExternalResult
    {
        $result = self::verified($redemption);

        return new ExternalResult(
            connectionId: $result->connectionId,
            issuer: $result->issuer,
            subject: $result->subject,
            tenantId: $result->tenantId,
            authenticatedAt: $renewal->authenticatedAt,
            sessionNotAfter: $redemption->sessionNotAfter,
            policyVersion: $redemption->enforcementVersion,
            evidence: self::evidence($renewal->evidence),
            linkId: $redemption->linkId,
            requestReference: $result->requestReference->value,
            nameIdFormat: $result->nameIdFormat,
        );
    }

    /**
     * The verified result the redemption carries.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\RedemptionResult  $redemption
     * @return \SineMacula\Laravel\Sso\Results\VerifiedResult
     *
     * @throws \LogicException
     */
    private static function verified(RedemptionResult $redemption): VerifiedResult
    {
        return $redemption->result ?? throw new \LogicException('An external result is built only from a redemption SSO redeemed.');
    }

    /**
     * The evidence SSO accepted, as `laravel-authentication`'s, if any.
     *
     * @param  ?\SineMacula\Laravel\Sso\Evidence\AcceptedEvidence  $evidence
     * @return ?\SineMacula\Laravel\Authentication\External\ExternalEvidence
     *
     * @throws \InvalidArgumentException
     */
    private static function evidence(?AcceptedEvidence $evidence): ?ExternalEvidence
    {
        return $evidence === null ? null : new ExternalEvidence($evidence->methods(), $evidence->rawContext(), $evidence->authenticatedAt);
    }
}
