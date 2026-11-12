<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Authorization;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authorization\Enums\GrantScopeStatus;
use SineMacula\Laravel\Authorization\Services\GrantScopeQuery;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Iam\Authorization\Translation\TenantTranslator;
use SineMacula\Laravel\Iam\Sso\IdentityReferences;
use SineMacula\Laravel\Iam\Tenancy\Contracts\GrantScope;
use SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict;

/**
 * Answers the grant half of SSO's principal scope from
 * `laravel-authorization`'s grant scope query.
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
            GrantScopeStatus::OUTSIDE => ScopeVerdict::OUTSIDE_TENANT,
            GrantScopeStatus::UNKNOWN => ScopeVerdict::UNKNOWN,
        };
    }
}
