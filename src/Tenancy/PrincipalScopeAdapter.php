<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Iam\Tenancy\Contracts\GrantScope;
use SineMacula\Laravel\Sso\Contracts\PrincipalScope;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict;

/**
 * Answers SSO's principal scope from the memberships and the grant scope:
 * `within_tenant` only when both are, `outside_tenant` when either is.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PrincipalScopeAdapter implements PrincipalScope
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Tenancy\IdentityMemberships  $memberships
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Reads the identity's memberships. */
        private IdentityMemberships $memberships,

        /** Resolves the grant half on every call. */
        private Container $container,
    ) {}

    /**
     * Where the identity's memberships and grants stand against the tenant.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $tenantId
     * @return \SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \LogicException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    #[\Override]
    public function judge(IdentityReference $identity, string $tenantId): ScopeVerdict
    {
        $resolved    = $this->memberships->identity($identity);
        $memberships = self::membershipsJudged($this->memberships->of($resolved), $tenantId);

        if ($memberships === ScopeVerdict::OUTSIDE_TENANT) {
            return $memberships;
        }

        $grants = $this->grants($resolved, $tenantId);

        return match (true) {
            $grants      === ScopeVerdict::OUTSIDE_TENANT                                           => ScopeVerdict::OUTSIDE_TENANT,
            $memberships === ScopeVerdict::WITHIN_TENANT && $grants === ScopeVerdict::WITHIN_TENANT => ScopeVerdict::WITHIN_TENANT,
            default                                                                                 => ScopeVerdict::UNKNOWN,
        };
    }

    /**
     * Where the identity's grants stand against the tenant.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $tenantId
     * @return \SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    private function grants(Identity $identity, string $tenantId): ScopeVerdict
    {
        return $this->container->make(GrantScope::class)->judge($identity, $tenantId);
    }

    /**
     * Where the memberships alone place the identity against the tenant.
     *
     * @param  \SineMacula\Laravel\Iam\Tenancy\MembershipSet  $memberships
     * @param  string  $tenantId
     * @return \SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict
     */
    private static function membershipsJudged(MembershipSet $memberships, string $tenantId): ScopeVerdict
    {
        // A partial read never latches a link suspended as `outside_tenant`.
        return match (true) {
            !$memberships->isComplete()            => ScopeVerdict::UNKNOWN,
            $memberships->reachesBeyond($tenantId) => ScopeVerdict::OUTSIDE_TENANT,
            default                                => ScopeVerdict::WITHIN_TENANT,
        };
    }
}
