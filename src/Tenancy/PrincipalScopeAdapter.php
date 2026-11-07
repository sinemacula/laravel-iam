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
 * SSO's principal scope, composed of the application's memberships and the
 * grant half (IAM-6.8, IAM-7.4, SSO-8.8): `within_tenant` only when both are,
 * `outside_tenant` when either is, and `unknown` otherwise.
 *
 * The membership half:
 *
 * - `outside_tenant` when a complete set holds a platform principal or a
 *   membership of any other tenant: the person reaches beyond the tenant;
 * - `within_tenant` when a complete set holds nothing else (a membership of the
 *   tenant, or none at all, since holding nothing widens nothing);
 * - `unknown` for a set marked incomplete, whatever it holds: SSO takes a set
 *   the application cannot read completely as `unknown`, and an
 *   `outside_tenant` answer latches a verified domain link suspended for good
 *   and revokes its sessions, which a partial read is never enough for.
 *
 * The grant half is `laravel-authorization`'s grant scope query (AUTHZ-14.2,
 * `GrantScope`), which has not shipped: until it does (M11) it is
 * `UnknownGrantScope`, so this answers `within_tenant` for nobody, and SSO
 * refuses every reservation and activation by a verified domain as
 * `principal_scope_unknown` (Q9). It still answers `outside_tenant` from the
 * memberships, fail closed: once bound over SSO's default, which answers
 * `unknown`, an existing verified domain link of a person who holds another
 * tenant's membership or a platform principal is latched suspended at its next
 * resolution, and the sessions through it are revoked. The grant half is asked
 * only when the memberships leave it open, so an answer of `outside_tenant`
 * from them asks nothing more.
 *
 * SSO asks it before a reservation, at its redemption and whenever a verified
 * domain link resolves. The identity resolves through the morph map and the
 * memberships are read on the write connection (`IdentityMemberships`); an
 * identity that cannot be resolved throws `UnresolvedReferenceException` inside
 * SSO's transaction (IAM-8.2), and whatever either half throws propagates,
 * which SSO takes as a store that cannot be reached: it refuses nothing and
 * suspends nothing. It takes no lock of its own: the membership half is read
 * under the application's membership guard (`Contracts\Memberships`), which
 * SSO's asking under its own locks puts after them. Stateless (IAM-8.1): the
 * grant half is resolved from the container on every call.
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
     * Where the identity's memberships and grants, together, stand against the
     * tenant.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $tenantId
     * @return \SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Iam\Exceptions\TenancyMisconfiguredException
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
     * Where the grant half places the identity's grants against the tenant.
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
        return match (true) {
            !$memberships->isComplete()            => ScopeVerdict::UNKNOWN,
            $memberships->reachesBeyond($tenantId) => ScopeVerdict::OUTSIDE_TENANT,
            default                                => ScopeVerdict::WITHIN_TENANT,
        };
    }
}
