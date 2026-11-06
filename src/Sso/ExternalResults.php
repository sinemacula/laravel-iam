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
 * admitted, and from nothing else (IAM-4.1, IAM-4.2, AUTH-3.10, SSO-9.2).
 *
 * Every value comes from the admitted redemption, never from anything the
 * client sent: the connection, issuer and subject from its verified result, the
 * tenant from the result's (the connection's), the provider's time from the
 * result's authentication context, the session's latest end from the
 * redemption's (the effective deadline, `null` when SSO's deadline contract
 * ignored the provider's), the policy version from the version of the
 * enforcement SSO judged under its locks (never the one the completion
 * checked), the evidence from what SSO's evidence contract accepted alone (its
 * methods, its raw context and its time, never the result's raw authentication
 * context), the link from the one the redemption resolved, the request
 * reference from the result's authorisation request, and the provider context
 * from the provenance SSO captured, in its stored form. A redemption that
 * accepted no evidence, or captured no provenance, gives the result none.
 *
 * `laravel-authentication` asks its link contract for the connection, issuer
 * and subject, and refuses the result as `link_mismatch` unless the answer is
 * exactly the link named, so a link removed and made again since the redemption
 * never stands in for it.
 *
 * A re-authentication's result is built the same way (`renewing()`), with the
 * provider's time and the evidence the renewal SSO asked for recorded, and no
 * provider context: `laravel-authentication` keeps the sign-in's, and records
 * none of a re-authentication's.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ExternalResults
{
    /**
     * The external result of the redemption SSO admitted for a sign-in.
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
        );
    }

    /**
     * The external result of the redemption SSO admitted for a
     * re-authentication, with the provider's time and the evidence of the
     * renewal SSO asked for, and no provider context.
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
        );
    }

    /**
     * The verified result the redemption carries, which only a redeemed one
     * does.
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
     * `laravel-authentication`'s evidence of what SSO's evidence contract
     * accepted, or `null` when it accepted nothing.
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
