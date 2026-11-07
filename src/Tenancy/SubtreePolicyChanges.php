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
 * Each is then judged with the strict cut-off of `laravel-authentication`'s
 * `tenantPolicyChanged()` (IAM-4.5), as `TenantPolicyChanges` judges one
 * tenant: once in place, as a savepoint of the transaction open on the storage
 * connection, and once more once that transaction commits. The pass after the
 * commit lists and resolves the subtree again, from the tree as it is then,
 * rather than judge the tenants the first pass listed: a move into the subtree
 * that commits while this change is open has judged the moved tenant's sessions
 * against the rule as it was before this change, so only a pass that reads the
 * tree once this change has committed finds that tenant. Of a change and a move
 * racing, whichever commits last judges the moved tenant against both. Every
 * session already recorded at the version it answers is skipped, so judging a
 * tenant again costs a read. The pass after the commit is held for the commit
 * of the innermost transaction open on the storage connection
 * (`AfterConnectionCommits`), never another connection's, and dropped by a
 * rollback; with no transaction open both passes run at once. Whatever the
 * tree, the resolver or a pass throws propagates: from this call, inside the
 * change's transaction, so it rolls back; from the commit, the change already
 * durable. Stateless (IAM-8.1): the tree is found on every pass.
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
     * Judge the sessions of the tenant and of every tenant below it, in place,
     * and once more, from the subtree as it then stands, once the transaction
     * open on the storage connection commits; answer how many sessions the
     * first pass revoked.
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
        $revoked = $this->judge($tenantId);

        $this->afterCommit->run($this->database->connection(StorageConnection::name()), function () use ($tenantId): void {

            $this->judge($tenantId);
        });

        return $revoked;
    }

    /**
     * List and resolve the subtree as the tree now answers it, then judge the
     * sessions of each tenant in it; answer how many sessions were revoked.
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
    private function judge(string $tenantId): int
    {
        $tenants  = array_map($this->tenants->tenant(...), $this->subtree($tenantId));
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
