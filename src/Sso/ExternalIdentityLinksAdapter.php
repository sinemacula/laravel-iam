<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Sso;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Contracts\ExternalIdentityLinks;
use SineMacula\Laravel\Authentication\External\ExternalLink;

/**
 * `laravel-authentication`'s external identity links, answered from the
 * redemption SSO admitted in this request alone.
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
     * The link SSO admitted for exactly the connection, issuer, subject and
     * NameID format.
     *
     * @param  string  $connectionId
     * @param  string  $issuer
     * @param  string  $subject
     * @param  ?string  $nameIdFormat
     * @return ?\SineMacula\Laravel\Authentication\External\ExternalLink
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     */
    #[\Override]
    public function find(string $connectionId, string $issuer, string $subject, ?string $nameIdFormat): ?ExternalLink
    {
        $redemption = $this->container->make(AdmittedRedemptions::class)->matching($connectionId, $issuer, $subject, $nameIdFormat);

        if ($redemption?->linkedIdentity === null || $redemption->linkId === null) {
            return null;
        }

        return new ExternalLink($this->identities->identity($redemption->linkedIdentity), $redemption->linkId);
    }
}
