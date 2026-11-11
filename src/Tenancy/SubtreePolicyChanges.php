<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy;

use Illuminate\Database\DatabaseManager;
use SineMacula\Laravel\Authentication\Database\StorageConnection;
use SineMacula\Laravel\Iam\Authorization\Translation\TenantTranslator;
use SineMacula\Laravel\Iam\Mfa\CurrentSession;
use SineMacula\Laravel\Iam\Transactions\AfterConnectionCommits;

/**
 * Judges the sessions of a tenant and every tenant below it, and of every
 * tenant the subtree gains before the storage connection's transaction commits
 * (IAM-7.5).
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
     * @param  \SineMacula\Laravel\Iam\Authorization\Translation\TenantTranslator  $translator
     * @param  \SineMacula\Laravel\Iam\Mfa\CurrentSession  $sessions
     * @param  \Illuminate\Database\DatabaseManager  $database
     * @param  \SineMacula\Laravel\Iam\Transactions\AfterConnectionCommits  $afterCommit
     */
    public function __construct(

        /** Finds `laravel-authorization`'s tenant tree on every pass. */
        private TenancyContracts $contracts,

        /** Resolves each tenant of the subtree on every pass. */
        private TenantReferences $tenants,

        /** Names each tenant of the subtree to `laravel-authorization`, and back. */
        private TenantTranslator $translator,

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
     * The tenant and every tenant below it; the tenant alone without a tree.
     *
     * @param  string  $tenantId
     * @return list<string>
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \UnexpectedValueException
     */
    private function subtree(string $tenantId): array
    {
        if ($this->contracts->tree() === null) {
            return [$tenantId];
        }

        return array_map($this->translator->idOf(...), $this->contracts->subtree($this->translator->toReference($tenantId)));
    }
}
