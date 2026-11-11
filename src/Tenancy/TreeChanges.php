<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Iam\Authorization\AuthorizationSeams;
use SineMacula\Laravel\Iam\Authorization\SubtreeGrantees;
use SineMacula\Laravel\Iam\Authorization\Translation\TenantTranslator;
use SineMacula\Laravel\Iam\Sso\IdentityGuards;
use SineMacula\Laravel\Sso\Config\Enums\Feature;
use SineMacula\Laravel\Sso\Config\Features;

/**
 * Applies a reported move of a tenant (IAM-7.5): passes it to
 * `laravel-authorization` while the application has a tree, and judges the
 * sessions of the moved tenant's subtree while anything a tenant requires can
 * follow the tree.
 *
 * Report a move inside the transaction that writes it, after the write, and a
 * removal as the move of each child moved out from under the removed tenant.
 * While grants are reported to SSO's scope widening, every identity granted in
 * the moved subtree is reported to it too, since no grant hook runs for a move.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final readonly class TreeChanges
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Tenancy\SubtreePolicyChanges  $subtrees
     * @param  \SineMacula\Laravel\Iam\Tenancy\TenantMfaRequirements  $requirements
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \SineMacula\Laravel\Iam\Authorization\Translation\TenantTranslator  $tenants
     * @param  \SineMacula\Laravel\Iam\Tenancy\ScopeWidenings  $widenings
     * @param  \SineMacula\Laravel\Iam\Sso\IdentityGuards  $guards
     */
    public function __construct(

        /** Judges the moved tenant's subtree in place, and once more once the transaction commits. */
        private SubtreePolicyChanges $subtrees,

        /** Tells whether the application has a tenant MFA requirement. */
        private TenantMfaRequirements $requirements,

        /** Resolves `laravel-authorization`'s manager on every call. */
        private Container $container,

        /** Holds the capabilities' switches. */
        private Repository $config,

        /** Names the moved tenant as `laravel-authorization` names it. */
        private TenantTranslator $tenants,

        /** Reports each identity granted in the moved subtree to SSO's scope widening. */
        private ScopeWidenings $widenings,

        /** Takes the guard of every identity granted in the moved subtree, in SSO's order, before any is reported. */
        private IdentityGuards $guards,
    ) {}

    /**
     * Report the move to `laravel-authorization` while the application has a
     * tree, then judge the moved tenant's subtree while SSO's enforcement or
     * MFA's tenant requirement is on; answer how many sessions were revoked.
     *
     * @param  string  $tenantId
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \Throwable
     */
    public function changed(string $tenantId): int
    {
        if (TenancyContracts::hasTree()) {
            $this->reportToAuthorization($tenantId);
        }

        if (!Features::enabled(Feature::ENFORCEMENT) && !$this->requirements->isConfigured()) {
            return 0;
        }

        return $this->subtrees->changed($tenantId);
    }

    /**
     * Report each identity granted in the moved subtree to SSO's scope
     * widening, every guard taken first in SSO's order, then the move to
     * `laravel-authorization`.
     *
     * @param  string  $tenantId
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \Throwable
     */
    private function reportToAuthorization(string $tenantId): void
    {
        if (AuthorizationSeams::reportsWidenings($this->config)) {

            $client   = new ClientContext(null, null);
            $grantees = $this->container->make(SubtreeGrantees::class)->of($tenantId);

            foreach ($this->guards->acquire($grantees) as $identity) {
                $this->widenings->widen($identity, $tenantId, $client);
            }
        }

        $this->container->make(AuthorizationManager::class)->treeChanged($this->tenants->toReference($tenantId));
    }
}
