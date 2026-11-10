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
 * Applies a change of the application's tenant tree to the sessions it may
 * concern (IAM-7.5): the application reports a tenant moved, once, and every
 * session acting in that tenant or below it is judged against the tenant
 * authentication policy as it now answers.
 *
 * The package sees only where a moved tenant ends up, never where it was, so it
 * cannot tell whether the move changed which tenant's rule applies. While SSO's
 * `enforcement` feature is on, or the application names or binds a tenant MFA
 * requirement (which may pass its answer down the tree itself, Q6), a report
 * judges the moved tenant and its whole subtree (Q7): broader than needed,
 * never narrower. With neither on nothing any tenant requires can have changed,
 * so nothing is judged and nothing is read. Each tenant is judged with
 * `laravel-authentication`'s strict cut-off (`SubtreePolicyChanges`): once in
 * place, as a savepoint of the transaction open on the storage connection, and
 * once more after it commits, the subtree listed again from the tree as it then
 * stands.
 *
 * Report a move inside the transaction that writes it, after the write, on the
 * storage connection (`Iam::transaction()` opens one), so the first pass reads
 * the tree as moved, judges each session against the rule the tenant now
 * inherits before the move commits, and rolls back with it. A removal is
 * reported the same way, after the write: the tenants moved out from under the
 * removed one (its children, which the application lists before it removes it)
 * are each a tenant moved, reported once the restructure is written, while the
 * sessions of the removed tenant itself, and of any tenant removed with it, are
 * `laravel-authentication`'s `tenantDeactivated()`'s. A report made before the
 * write would judge the tree as it was, leaving a session the new structure no
 * longer allows to the pass after the commit. Every tenant of the subtree
 * resolves through `laravel-authentication`'s tenant resolver
 * (`TenantReferences`); one that cannot be resolved throws
 * `UnresolvedReferenceException` (IAM-8.2), as does a tree that cannot list the
 * subtree, so the move rolls back rather than leave sessions unjudged.
 *
 * The change is passed on, first and whatever SSO's enforcement and the
 * requirement say, to `laravel-authorization`, while the authorization
 * capability's switch (`iam.adapters.authorization`) is on and the application
 * names or binds its tree (`TenancyContracts::hasTree()`, as the tree is bound
 * to `laravel-authorization` only then, `Authorization\TenantTreeAdapter`):
 *
 * - while its grants are reported to SSO's scope widening too
 *   (`AuthorizationSeams::reportsWidenings()`, the SSO capability's switch on
 *   as well), every identity holding a live grant rooted at the moved tenant or
 *   below it (`Authorization\SubtreeGrantees`) is reported to SSO's scope
 *   widening in the moved tenant (`ScopeWidenings::widen()`, IAM-6.7): the
 *   grant half of the principal scope counts a grant below a tenant within it,
 *   so a move that takes the subtree out from under a tenant widens the scope
 *   of every person granted in it without a grant being written, and no grant
 *   hook runs. SSO suspends each one's links by a verified domain in every
 *   other tenant's connections, and revokes the sessions established through
 *   them, in the move's transaction. Every one's identity guard is taken first,
 *   in SSO's order (`Sso\IdentityGuards`), before any connection is locked:
 *   taken one widening after another, a guard would follow another identity's
 *   connections, and the move would deadlock with a grant, a reservation or an
 *   activation of that identity, which holds its guard and waits for one of
 *   those connections. The package cannot tell a move out from under a tenant
 *   from one within it, so this is broader than needed, never narrower: a link
 *   in a tenant the subtree still stands below is suspended
 *   too, latched as SSO latches every suspension, and is linked again;
 * - the moved tenant is reported to `laravel-authorization`
 *   (`Authorization::treeChanged()`, AUTHZ-12.8), which drops every resolution
 *   built in it or below it, in every worker, at once and again once the
 *   transaction commits, and has a delegated grant call running meanwhile tried
 *   again. One report covers the moved tenant's whole subtree, since its
 *   entries pin the tenant's chain.
 *
 * The tenant is named to it as this package names a tenant to
 * `laravel-authorization` (`Authorization\Translation\TenantTranslator`),
 * through `laravel-authentication`'s tenant resolver, which `iam:check` makes
 * mandatory alongside a tree, so a tenant that cannot be resolved, or that
 * `laravel-authorization` cannot read, throws `UnresolvedReferenceException`
 * and the move rolls back; a failure of `laravel-authorization`'s cache store
 * or of SSO's widening propagates the same way. Without a tree
 * `laravel-authorization` keeps its own flat tree, which no move changes, and
 * nothing is reported to it. With the switch off, the application binds
 * `laravel-authorization`'s tree itself, and reports to it itself. The client
 * of every widening is unknown (`new ClientContext(null, null)`): a move is the
 * application's, never a request's. Stateless (IAM-8.1).
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

        /** Holds the authorization capability's switch. */
        private Repository $config,

        /** Names the moved tenant as `laravel-authorization` names it. */
        private TenantTranslator $tenants,

        /** Reports each identity granted in the moved subtree to SSO's scope widening. */
        private ScopeWidenings $widenings,

        /** Takes the guard of every identity granted in the moved subtree, in SSO's order, before any is reported. */
        private IdentityGuards $guards,
    ) {}

    /**
     * Report the identities granted in the moved tenant's subtree to SSO's
     * scope widening, and the move to `laravel-authorization`, while the
     * authorization capability is on beside the application's tree, then judge
     * the sessions of the tenant moved, and of every tenant below it, once the
     * move is written, while anything a tenant requires can follow the tree;
     * answer how many sessions the first passes revoked.
     *
     * @param  string  $tenantId
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Iam\Exceptions\TenancyMisconfiguredException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException
     * @throws \Throwable
     */
    public function changed(string $tenantId): int
    {
        if (AuthorizationSeams::isOn($this->config) && TenancyContracts::hasTree($this->container, $this->config)) {
            $this->reportToAuthorization($tenantId);
        }

        if (!Features::enabled(Feature::ENFORCEMENT) && !$this->requirements->isConfigured()) {
            return 0;
        }

        return $this->subtrees->changed($tenantId);
    }

    /**
     * Report each identity granted in the moved tenant's subtree to SSO's scope
     * widening, every one's guard taken first in SSO's order, while
     * `laravel-authorization`'s grants are reported to it, then the move to
     * `laravel-authorization`.
     *
     * @param  string  $tenantId
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
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
