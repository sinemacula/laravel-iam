<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy;

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
 * subtree, so the move rolls back rather than leave sessions unjudged. Passing
 * the change on to the members that cache by tenant (`laravel-authorization`'s
 * `treeChanged()`, AUTHZ-12.8) comes with M11. Stateless (IAM-8.1).
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
     */
    public function __construct(

        /** Judges the moved tenant's subtree in place, and once more once the transaction commits. */
        private SubtreePolicyChanges $subtrees,

        /** Tells whether the application has a tenant MFA requirement. */
        private TenantMfaRequirements $requirements,
    ) {}

    /**
     * Judge the sessions of the tenant moved, and of every tenant below it,
     * once the move is written, while anything a tenant requires can follow the
     * tree; answer how many sessions the first passes revoked.
     *
     * @param  string  $tenantId
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Iam\Exceptions\TenancyMisconfiguredException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \Throwable
     */
    public function changed(string $tenantId): int
    {
        if (!Features::enabled(Feature::ENFORCEMENT) && !$this->requirements->isConfigured()) {
            return 0;
        }

        return $this->subtrees->changed($tenantId);
    }
}
