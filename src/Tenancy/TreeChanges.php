<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Services\GrantScopeQuery;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Iam\Authorization\AuthorizationSeams;
use SineMacula\Laravel\Iam\Authorization\Translation\TenantTranslator;
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
 * While grants are reported to SSO's scope widening, the identities granted in
 * the moved subtree are reported to it too, as no grant hook runs for a move.
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
     */
    public function __construct(

        /** Judges the moved tenant's subtree in place, and once more once the transaction commits. */
        private SubtreePolicyChanges $subtrees,

        /** Tells whether the application has a tenant MFA requirement. */
        private TenantMfaRequirements $requirements,

        /** Resolves `laravel-authorization`'s services on every call. */
        private Container $container,

        /** Holds the capabilities' switches. */
        private Repository $config,

        /** Names the moved tenant as `laravel-authorization` names it. */
        private TenantTranslator $tenants,

        /** Reports each identity granted in the moved subtree to SSO's scope widening. */
        private ScopeWidenings $widenings,
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
     * Report the identities granted in the moved subtree to SSO's scope
     * widening, together, then the move to `laravel-authorization`.
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
        $tenant = $this->tenants->toReference($tenantId);

        if (AuthorizationSeams::reportsWidenings($this->config)) {

            $identities = [];

            foreach ($this->container->make(GrantScopeQuery::class)->granteesWithin($tenant) as $grantee) {

                $identity = self::identityOf($grantee);

                if ($identity === null) {
                    continue;
                }

                $identities[] = $identity;
            }

            $this->widenings->widen($identities, $tenantId, new ClientContext(null, null));
        }

        $this->container->make(AuthorizationManager::class)->treeChanged($tenant);
    }

    /**
     * The identity behind the grantee, a principal's for a principal; `null`
     * for a grantee that is no model, one of another kind, or one gone.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     */
    private static function identityOf(Reference $grantee): ?Identity
    {
        $class = Relation::getMorphedModel($grantee->type) ?? $grantee->type;

        if (!is_a($class, Model::class, true)) {
            return null;
        }

        $blank = new $class;
        $found = WriteConnection::during($blank, static fn (): ?Model => WriteConnection::query($blank->newQuery())->find($grantee->id));

        return match (true) {
            $found instanceof Principal => $found->getIdentity(),
            $found instanceof Identity  => $found,
            default                     => null,
        };
    }
}
