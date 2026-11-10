<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Authorization;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authorization\Enums\GrantScopeStatus;
use SineMacula\Laravel\Authorization\Services\GrantScopeQuery;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\TenantChain;
use SineMacula\Laravel\Iam\Authorization\Translation\TenantTranslator;
use SineMacula\Laravel\Iam\Sso\IdentityReferences;
use SineMacula\Laravel\Iam\Tenancy\Contracts\GrantScope;
use SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict;

/**
 * The grant half of SSO's principal scope, answered by
 * `laravel-authorization`'s grant scope query (IAM-6.8, AUTHZ-14.2): where the
 * live grants of an identity and of every principal it owns lie against a
 * tenant. `within` becomes `within_tenant`, `outside` `outside_tenant`, and
 * `unknown` stays `unknown`; the membership half is composed with it by
 * `Tenancy\PrincipalScopeAdapter`, `within_tenant` only when both are.
 *
 * The query counts the principals `laravel-authorization`'s identity directory
 * lists, which this package answers from `laravel-authentication`'s principals
 * (`IdentityDirectoryAdapter`), and answers `within` only for a complete list.
 * It reads the grants on the write connection, in a savepoint of the caller's
 * transaction, nesting the tenant tree's subtree in its query (bound to the
 * application's tree, `TenantTreeAdapter`), so a tree on another connection
 * than `authorization.connection` cannot be read there and answers `unknown`
 * unless a platform-wide grant proves `outside`. The subtree names each of its
 * tenants by the type of the tenant asked about, so a tenant below it of
 * another type would read its grants as rooted elsewhere: an `outside` answer
 * read from the application's tree is given only once its subtree's tenants are
 * confirmed to be of one type (`TenantTreeAdapter::tenantsIn()`), and a tree
 * that nests two types throws `TenancyMisconfiguredException` rather than have
 * SSO suspend a link for a grant below the tenant.
 *
 * The identity is named by its morph class and key (`IdentityReferences`), and
 * the tenant through `laravel-authentication`'s tenant resolver
 * (`TenantTranslator`); an identity that is no Eloquent model, and a tenant
 * that cannot be resolved, or whose key is not its identifier, throw
 * `UnresolvedReferenceException` (IAM-8.2), which SSO takes as a store it
 * cannot reach, refusing nothing and suspending nothing. Whatever the query
 * throws propagates. It takes no lock, reads no request, and keeps nothing
 * between calls (IAM-8.1): the query is resolved from the container on every
 * call, so it is transient.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class GrantScopeAdapter implements GrantScope
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Iam\Sso\IdentityReferences  $identities
     * @param  \SineMacula\Laravel\Iam\Authorization\Translation\TenantTranslator  $tenants
     */
    public function __construct(

        /** Resolves `laravel-authorization`'s grant scope query on every call. */
        private Container $container,

        /** Names the identity by its morph class and key. */
        private IdentityReferences $identities,

        /** Names the tenant as `laravel-authorization` names it. */
        private TenantTranslator $tenants,
    ) {}

    /**
     * Where the identity's grants stand against the tenant.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $tenantId
     * @return \SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    #[\Override]
    public function judge(Identity $identity, string $tenantId): ScopeVerdict
    {
        $reference = $this->identities->reference($identity);
        $tenant    = $this->tenants->toReference($tenantId);
        $status    = $this->container->make(GrantScopeQuery::class)->forIdentity(new Reference($reference->type, $reference->id), $tenant);

        return match ($status) {
            GrantScopeStatus::WITHIN  => ScopeVerdict::WITHIN_TENANT,
            GrantScopeStatus::OUTSIDE => $this->outside($tenant),
            GrantScopeStatus::UNKNOWN => ScopeVerdict::UNKNOWN,
        };
    }

    /**
     * `outside_tenant`, once the tenant's subtree, while the application's tree
     * is the one `laravel-authorization` reads (`TenantChain::tree()`, as its
     * grant scope query reads it), holds no tenant of another type, which the
     * query would have read as rooted elsewhere.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return \SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\TenancyMisconfiguredException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    private function outside(Reference $tenant): ScopeVerdict
    {
        $tree = TenantChain::tree();

        if ($tree instanceof TenantTreeAdapter) {
            $tree->tenantsIn($tenant);
        }

        return ScopeVerdict::OUTSIDE_TENANT;
    }
}
