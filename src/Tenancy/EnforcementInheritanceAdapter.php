<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Iam\Authorization\Translation\TenantTranslator;
use SineMacula\Laravel\Sso\Contracts\EnforcementInheritance;
use SineMacula\Laravel\Sso\Enforcement\EnforcementService;

/**
 * Answers SSO's enforcement inheritance from `laravel-authorization`'s tenant
 * tree: the nearest tenant, from the one asked up, with a stored rule.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class EnforcementInheritanceAdapter implements EnforcementInheritance
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Iam\Tenancy\TenancyContracts  $contracts
     * @param  \SineMacula\Laravel\Iam\Authorization\Translation\TenantTranslator  $tenants
     */
    public function __construct(

        /** Resolves SSO's reader of the stored rules on every call. */
        private Container $container,

        /** Finds `laravel-authorization`'s tenant tree on every call. */
        private TenancyContracts $contracts,

        /** Names a tenant to the tree, and each ancestor back. */
        private TenantTranslator $tenants,
    ) {}

    /**
     * The nearest tenant from the tenant up with a rule, else the tenant.
     *
     * @param  string  $tenantId
     * @param  string  $application
     * @return string
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \Throwable
     */
    #[\Override]
    public function enforcingTenant(string $tenantId, string $application): string
    {
        $tree  = $this->contracts->tree();
        $rules = $this->container->make(EnforcementService::class);

        if ($tree === null || $rules->get($tenantId)->version !== null) {
            return $tenantId;
        }

        foreach ($tree->ancestors($this->tenants->toReference($tenantId)) as $ancestor) {

            $ancestorId = $this->tenants->idOf($ancestor);

            if ($rules->get($ancestorId)->version !== null) {
                return $ancestorId;
            }
        }

        return $tenantId;
    }
}
