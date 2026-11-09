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
 * `laravel-authorization`'s authentication context, answered by
 * `laravel-authentication`'s (IAM-6.2, AUTHZ-13.2, AUTH-11.8): the
 * `authentication` namespace with `laravel-authentication`'s own key names
 * (`identity_id`, `principal_id`, `tenant_id`, `application`, `amr`,
 * `auth_time`, `mfa`, `multifactor`, `seconds_since_step_up`, `credential`,
 * `scopes`, `ip` and the rest), and the `mfa` and `sso` namespaces its
 * contributors add, each keyed as `laravel-authentication` holds it. Nothing is
 * renamed or worked out here: what a key means is its member's.
 *
 * The namespaces are a fixed list, `authentication`, `mfa` and `sso`, never the
 * contributors registered when it is asked: `laravel-authorization` asks as it
 * boots, and builds its key catalogue once, both before this package registers
 * its `mfa` and `sso` contributors, once every provider has booted, and a
 * namespace missing then would leave its assurance keys testable for good.
 * Naming one that holds no keys, its capability switched off, costs nothing:
 * its keys are absent. A namespace an application's own contributor adds is not
 * supplied here; a source of its own supplies it
 * (`authorization.context.sources`).
 *
 * The contract takes nothing, so the values are the request's: the context
 * `laravel-authentication` holds for the default guard, the one the route's
 * `auth` middleware authenticated with (`AuthenticationContexts::current()`),
 * built at most once per authentication state; none for a guest or a guard that
 * is not `laravel-authentication`'s, so every key is missing. The keys are
 * declared to `laravel-authorization`'s key catalogue apart
 * (`AuthenticationContextKeys`). Since the values depend on the request alone,
 * never on the record a check is about, it is scope invariant, so
 * `whereAuthorized()` reads it once for a query.
 *
 * `laravel-authentication`'s authentication contexts are resolved as the values
 * are asked for, never as it is built: `laravel-authorization` builds it as it
 * boots, before a `laravel-authentication` registered from another provider's
 * `boot()` has bound them. It holds nothing between calls (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AuthenticationContextAdapter implements AuthenticationContext, ScopeInvariant
{
    /** @var list<string> The namespaces supplied: `laravel-authentication`'s own, then those MFA's and SSO's contributors add. */
    public const array NAMESPACES = [Context::NAMESPACE, MfaContributor::NAMESPACE, SsoContext::NAMESPACE];

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The container `laravel-authentication`'s authentication contexts are resolved from, as the values are asked for. */
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
     * The request's authentication context, by namespace, then by key: only the
     * namespaces supplied, and none for a guest.
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
