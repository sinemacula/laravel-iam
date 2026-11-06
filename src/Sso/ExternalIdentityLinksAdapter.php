<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Contracts\ExternalIdentityLinks;
use SineMacula\Laravel\Authentication\External\ExternalLink;

/**
 * `laravel-authentication`'s external identity links, answered from the
 * redemption SSO admitted in this request alone (IAM-4.3, AUTH-3.9, SSO-8.3).
 *
 * Links are SSO's: `laravel-authentication` stores none, and asks this contract
 * for the connection, issuer and subject of the result it is handed, inside the
 * redemption's transaction, after SSO's locks. The answer is the link SSO's
 * admission resolved under those locks (`AdmittedRedemptions`): the identity
 * its linked identity names and its link id, when the connection, issuer and
 * subject are exactly the admitted result's, compared byte for byte, and `null`
 * otherwise, with no redemption admitted among them. No link is ever looked up
 * again, by email, by any attribute or by issuer and subject alone: a SAML link
 * is keyed by the `NameID` format as well, which this contract is not handed,
 * and a second lookup after SSO's locks could find another link. So
 * `laravel-authentication` refuses the result unless the link it names is
 * exactly the one SSO admitted (`link_mismatch`), and a link removed and made
 * again for the same identity is another link.
 *
 * The linked identity resolves through the morph map (`IdentityReferences`);
 * one that does not throws `UnresolvedReferenceException` (IAM-8.2), which
 * reaches `laravel-authentication`'s caller and rolls the redemption back.
 *
 * The record is resolved from the container on every call, so the answer is
 * always this request's or this job's admission and never one another kept
 * (IAM-8.1); the adapter itself keeps nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ExternalIdentityLinksAdapter implements ExternalIdentityLinks
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Iam\Sso\IdentityReferences  $identities
     */
    public function __construct(

        /** Resolves this request's admitted redemption on every call. */
        private Container $container,

        /** Resolves the identity the admitted redemption linked. */
        private IdentityReferences $identities,
    ) {}

    /**
     * The link SSO admitted in this request for exactly the connection, issuer
     * and subject, with the identity it maps to, or `null` when it admitted
     * none for them.
     *
     * @param  string  $connectionId
     * @param  string  $issuer
     * @param  string  $subject
     * @return ?\SineMacula\Laravel\Authentication\External\ExternalLink
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    #[\Override]
    public function find(string $connectionId, string $issuer, string $subject): ?ExternalLink
    {
        $redemption = $this->container->make(AdmittedRedemptions::class)->matching($connectionId, $issuer, $subject);

        if ($redemption?->linkedIdentity === null || $redemption->linkId === null) {
            return null;
        }

        return new ExternalLink($this->identities->identity($redemption->linkedIdentity), $redemption->linkId);
    }
}
