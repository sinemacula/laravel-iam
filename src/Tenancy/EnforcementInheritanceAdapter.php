<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy;

use SineMacula\Laravel\Iam\Authorization\Translation\TenantTranslator;
use SineMacula\Laravel\Sso\Contracts\EnforcementInheritance;

/**
 * Answers SSO's enforcement inheritance from `laravel-authorization`'s tenant
 * tree: the path from the tenant up to the nearest tenant with a stored rule.
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
     * @param  \SineMacula\Laravel\Iam\Tenancy\TenancyContracts  $contracts
     * @param  \SineMacula\Laravel\Iam\Authorization\Translation\TenantTranslator  $tenants
     */
    public function __construct(

        /** Finds `laravel-authorization`'s tenant tree on every call. */
        private TenancyContracts $contracts,

        /** Names a tenant to the tree, and each ancestor back. */
        private TenantTranslator $tenants,
    ) {}

    /**
     * The tenant up to the nearest tenant with a rule, else up to its root.
     *
     * @param  string  $tenantId
     * @param  string  $application
     * @param  \Closure(string): bool  $isConfigured
     * @return non-empty-list<string>
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \Throwable
     */
    #[\Override]
    public function enforcementPath(string $tenantId, string $application, \Closure $isConfigured): array
    {
        $tree = $this->contracts->tree();

        if ($tree === null || $isConfigured($tenantId)) {
            return [$tenantId];
        }

        $path = [$tenantId];

        foreach ($tree->ancestors($this->tenants->toReference($tenantId)) as $ancestor) {

            $ancestorId = $this->tenants->idOf($ancestor);
            $path[]     = $ancestorId;

            if ($isConfigured($ancestorId)) {
                break;
            }
        }

        return $path;
    }
}
