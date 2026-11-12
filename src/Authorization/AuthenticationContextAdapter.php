<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Authorization;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Context\AuthenticationContext as Context;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationContexts;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationContext;
use SineMacula\Laravel\Authorization\Contracts\ScopeInvariant;
use SineMacula\Laravel\Mfa\Context\AuthenticationContextContributor as MfaContributor;
use SineMacula\Laravel\Sso\Sessions\AuthenticationContext as SsoContext;

/**
 * Answers `laravel-authorization`'s authentication context from
 * `laravel-authentication`'s `authentication`, `mfa` and `sso` namespaces.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AuthenticationContextAdapter implements AuthenticationContext, ScopeInvariant
{
    /** @var list<string> The namespaces supplied, fixed since `laravel-authorization` reads them before the contributors register. */
    public const array NAMESPACES = [Context::NAMESPACE, MfaContributor::NAMESPACE, SsoContext::NAMESPACE];

    /** @var list<string> The assurance keys beside `laravel-authorization`'s own: `laravel-authentication`'s, MFA's, then SSO's. */
    public const array ASSURANCE_KEYS = [
        'mfa',
        'recovery_code',
        'accepted',
        'factor_types',
        'level',
        'phishing_resistant',
        'user_verification',
        'last_verification_age_seconds',
        'provider_auth_time',
        'provider_amr',
        'provider_acr',
        'provider_authn_context_class_ref',
    ];

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Resolves `laravel-authentication`'s contexts lazily, since they may be bound after this is built. */
        private Container $container,
    ) {}

    /**
     * The namespaces supplied: `authentication`, `mfa` and `sso`.
     *
     * @return list<string>
     */
    #[\Override]
    public function namespaces(): array
    {
        return self::NAMESPACES;
    }

    /**
     * The assurance keys beside `laravel-authorization`'s own.
     *
     * @return list<string>
     */
    #[\Override]
    public function assuranceKeys(): array
    {
        return self::ASSURANCE_KEYS;
    }

    /**
     * The request's authentication context by namespace, empty for a guest.
     *
     * @return array<string, array<string, mixed>>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    #[\Override]
    public function values(): array
    {
        $context = $this->container->make(AuthenticationContexts::class)->current();

        return $context === null ? [] : array_intersect_key($context->toArray(), array_flip(self::NAMESPACES));
    }
}
