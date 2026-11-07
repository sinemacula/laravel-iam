<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Iam\Contracts\TenantTree;
use SineMacula\Laravel\Iam\Exceptions\TenancyMisconfiguredException;
use SineMacula\Laravel\Sso\Contracts\EnforcementInheritance;
use SineMacula\Laravel\Sso\Enforcement\EnforcementService;

/**
 * SSO's enforcement inheritance, answered from the application's tenant tree
 * (IAM-7.5, SSO-4.2): the nearest tenant, from the one asked up through its
 * ancestors, that has a rule, on or off; the tenant asked when none on the way
 * has.
 *
 * Each tenant's rule is read through SSO's own reader of what is stored
 * (`EnforcementService::get()`), on the write connection, one tenant at a time,
 * nearest first, stopping at the first that has one, a stored version: never
 * through SSO's `Enforcement::policy()`, which asks this contract and would
 * recurse. A rule that is on requires a sign-in through one of its connections
 * whatever they are, so a rule on with no connection left still enforces. A
 * rule turned off is still the tenant's rule and keeps the question there, so a
 * rule turned off only ever loosens what applies to its tenant and to every
 * tenant inheriting from it, and SSO, which revokes nothing when a rule is
 * turned off, leaves no session out of compliance; a tenant whose rule is off
 * thereby opts out of its ancestors' rules, as whoever may change a tenant's
 * rule (the application's authorisation) decides. Only a tenant never
 * configured, with no row or only the unconfigured row SSO's lock inserts,
 * passes the question up. The rule is the tenant's for every application, so
 * the application asked does not change the answer.
 *
 * The tree answers the ancestors nearest first, the tenant excluded; one that
 * answers the tenant among them, a tenant twice, or a blank id has a cycle or
 * is broken, and is refused with a `LogicException`, never followed. Every id
 * it answers is a tenant id SSO can store a rule for, or SSO's reader refuses
 * it.
 *
 * SSO asks it inside an admission's transaction, before its lock of the
 * enforcing tenant's rule and again under it (`LockedEnforcement::isCurrent()`,
 * a changed answer refusing `connection_unavailable`), and whenever it judges a
 * session's policy. The reads take no lock, so they never invert SSO's order
 * against a change of a rule, which locks only its own tenant's row and then
 * judges the sessions of its subtree; and inside a transaction that has already
 * read, at REPEATABLE READ, they answer as of its snapshot. So an ancestor's
 * rule turned on while a descendant's sign-in is admitted may be read as it
 * was: the sign-in is then judged against the rule it read, and its session is
 * revoked by the change's second pass when it commits before that pass runs,
 * and judged at its first refresh otherwise (a member gap SSO's lock of the
 * enforcing tenant alone leaves). Whatever the tree or SSO's reader throws
 * propagates. Stateless (IAM-8.1): the tree and SSO's reader are resolved on
 * every call.
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
     */
    public function __construct(

        /** Resolves SSO's reader of the stored rules on every call. */
        private Container $container,

        /** Finds the application's tenant tree on every call. */
        private TenancyContracts $contracts,
    ) {}

    /**
     * The tenant whose rule applies to sessions active in the tenant: the
     * nearest, from the tenant up, that has a rule, or the tenant itself.
     *
     * @param  string  $tenantId
     * @param  string  $application
     * @return string
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Iam\Exceptions\TenancyMisconfiguredException
     * @throws \Throwable
     */
    #[\Override]
    public function enforcingTenant(string $tenantId, string $application): string
    {
        $rules = $this->container->make(EnforcementService::class);

        foreach (self::path($tenantId, $this->tree()->ancestors($tenantId)) as $candidate) {
            if ($rules->get($candidate)->version !== null) {
                return $candidate;
            }
        }

        return $tenantId;
    }

    /**
     * The application's tenant tree, which the adapter is never asked without.
     *
     * @return \SineMacula\Laravel\Iam\Contracts\TenantTree
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\TenancyMisconfiguredException
     */
    private function tree(): TenantTree
    {
        return $this->contracts->tree() ?? throw TenancyMisconfiguredException::forNone(TenancyContracts::TREE, TenantTree::class);
    }

    /**
     * The tenant and its ancestors, nearest first, refusing a path that holds a
     * tenant twice or a blank id.
     *
     * @param  string  $tenantId
     * @param  array<array-key, mixed>  $ancestors
     * @return list<string>
     *
     * @throws \LogicException
     */
    private static function path(string $tenantId, array $ancestors): array
    {
        $path = [$tenantId];

        foreach ($ancestors as $ancestor) {

            if (!is_string($ancestor) || trim($ancestor) === '' || in_array($ancestor, $path, true)) {
                throw new \LogicException('The tenant tree answered an ancestor that is blank, repeated or the tenant itself, so it has a cycle or is broken.');
            }

            $path[] = $ancestor;
        }

        return $path;
    }
}
