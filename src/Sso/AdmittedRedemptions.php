<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

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
 * another link. `laravel-authentication`'s external evidence policy accepts a
 * provider's evidence only as the evidence SSO's evidence contract accepted in
 * this same redemption, for the identity it linked (`acceptedEvidence()`).
 *
 * The client the redemption is made for is recorded with it, as SSO was handed
 * it for the admission, so SSO's exemption gate, asked by the tenant
 * authentication policy while `laravel-authentication` judges that very sign-in
 * or re-authentication, is handed the client of the request being judged
 * (`clientFor()`), and an `ExemptionUsed` it reports carries that request's IP
 * address and user agent.
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

    /** @var ?\SineMacula\Laravel\Sso\Http\ClientContext The client the admitted redemption is made for, as SSO was handed it, answered only while that redemption is held. */
    private ?ClientContext $client = null;

    /**
     * Record the redemption SSO admitted, with the identity and the link it
     * resolved, and the client it is made for, as SSO was handed it.
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
     * The connection of the redemption admitted in this request when it links
     * exactly the identity given, or `null` otherwise: the connection a sign-in
     * of that identity is being established through, before
     * `laravel-authentication` has written its session.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return ?string
     */
    public function connectionFor(IdentityReference $identity): ?string
    {
        $admitted = $this->admitted;

        return $admitted?->linkedIdentity !== null && $admitted->linkedIdentity->is($identity) ? $admitted->result?->connectionId : null;
    }

    /**
     * The client the redemption admitted in this request is made for when it
     * links exactly the identity given and names exactly the session given, or
     * none for a sign-in, whose session is not written yet; `null` otherwise:
     * the client of the request in which `laravel-authentication` judges that
     * sign-in, or that session's re-authentication.
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
     * The evidence SSO's evidence contract accepted in the redemption admitted
     * in this request through the connection, when that redemption links
     * exactly the identity given, or `null` when no redemption through it of
     * that identity is admitted or it accepted none.
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
     * Forget the redemption admitted, if any.
     *
     * @return void
     */
    public function forget(): void
    {
        $this->admitted = null;
    }
}
