<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy;

use Illuminate\Database\DatabaseManager;
use SineMacula\Laravel\Authentication\Database\StorageConnection;
use SineMacula\Laravel\Iam\Mfa\CurrentSession;
use SineMacula\Laravel\Iam\Transactions\AfterConnectionCommits;

/**
 * Applies a change that may reach a whole subtree of the application's tenant
 * tree to the sessions acting in it (IAM-7.5): a change of an enforcing
 * tenant's rule, which every tenant below may inherit, and a reported move of a
 * tenant, which may change what every tenant below inherits.
 *
 * The tenant and every tenant below it are listed from the tree, the tenant
 * first, each once; without a tree every tenant stands alone, and the subtree
 * is the tenant itself. A blank id, the tenant itself among its descendants, or
 * a descendant answered twice is refused with a `LogicException` as soon as the
 * tree answers it, as the inheritance adapter refuses an ancestor answered
 * twice: the tree has a cycle or is broken, and a tree that answers lazily
 * might otherwise go on answering a cycle below the tenant for ever, inside the
 * transaction holding SSO's locks or the move's. Every tenant listed is
 * resolved through `laravel-authentication`'s tenant resolver
 * (`TenantReferences`) before any is judged, so one that cannot be resolved
 * throws `UnresolvedReferenceException` (IAM-8.2) with nothing judged, and the
 * change rolls back rather than leave a subtree judged in part.
 *
 * Each is judged through `laravel-authentication`'s `tenantPolicyChanged()`
 * (IAM-4.5), which judges it again once the change's transaction commits. A
 * move into the subtree that commits while this change is open judged the moved
 * tenant against the rule as it was, so once the transaction open on the
 * storage connection commits (`AfterConnectionCommits`) the subtree is listed
 * again and every tenant the first listing missed is judged too. A rollback
 * drops that pass; with no transaction open it runs at once. Whatever the tree,
 * the resolver or a pass throws propagates.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SubtreePolicyChanges
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Tenancy\TenancyContracts  $contracts
     * @param  \SineMacula\Laravel\Iam\Tenancy\TenantReferences  $tenants
     * @param  \SineMacula\Laravel\Iam\Mfa\CurrentSession  $sessions
     * @param  \Illuminate\Database\DatabaseManager  $database
     * @param  \SineMacula\Laravel\Iam\Transactions\AfterConnectionCommits  $afterCommit
     */
    public function __construct(

        /** Finds the application's tenant tree on every pass. */
        private TenancyContracts $contracts,

        /** Resolves each tenant of the subtree on every pass. */
        private TenantReferences $tenants,

        /** Resolves the session service both passes go through. */
        private CurrentSession $sessions,

        /** Resolves the storage connection whose commit the second pass waits for. */
        private DatabaseManager $database,

        /** Holds the second pass for that connection's own transaction. */
        private AfterConnectionCommits $afterCommit,
    ) {}

    /**
     * Judge the sessions of the tenant and of every tenant below it, and of
     * every tenant the subtree has gained once the storage connection's
     * transaction commits; answer how many sessions the first pass revoked.
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
        $listed  = $this->subtree($tenantId);
        $revoked = $this->judge($listed);

        $this->afterCommit->run($this->database->connection(StorageConnection::name()), function () use ($tenantId, $listed): void {

            $this->judge(array_diff($this->subtree($tenantId), $listed));
        });

        return $revoked;
    }

    /**
     * Resolve every tenant given, then judge the sessions of each; answer how
     * many sessions were revoked.
     *
     * @param  array<int, string>  $tenantIds
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \Throwable
     */
    private function judge(array $tenantIds): int
    {
        $tenants  = array_map($this->tenants->tenant(...), $tenantIds);
        $sessions = $this->sessions->identitySessions();
        $revoked  = 0;

        foreach ($tenants as $tenant) {
            $revoked += $sessions->tenantPolicyChanged($tenant);
        }

        return $revoked;
    }

    /**
     * The tenant, then every tenant below it, each once.
     *
     * @param  string  $tenantId
     * @return list<string>
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Iam\Exceptions\TenancyMisconfiguredException
     * @throws \Throwable
     */
    private function subtree(string $tenantId): array
    {
        $tree = $this->contracts->tree();

        if ($tree === null) {
            return [$tenantId];
        }

        $subtree = [$tenantId];

        foreach ($tree->descendants($tenantId) as $descendant) {

            self::assertDescendant($subtree, $descendant);

            $subtree[] = $descendant;
        }

        return $subtree;
    }

    /**
     * Refuse a descendant that is blank or already listed, the tenant itself
     * among them: the tree has a cycle or is broken.
     *
     * @param  non-empty-list<string>  $subtree
     * @param  string  $descendant
     * @return void
     *
     * @throws \LogicException
     */
    private static function assertDescendant(array $subtree, string $descendant): void
    {
        if (trim($descendant) === '' || in_array($descendant, $subtree, true)) {
            throw new \LogicException('The tenant tree answered a descendant that is blank, repeated or the tenant itself, so it has a cycle or is broken.');
        }
    }
}
