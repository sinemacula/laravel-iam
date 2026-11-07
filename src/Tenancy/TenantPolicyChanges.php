<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Tenancy;

use Illuminate\Database\DatabaseManager;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Database\StorageConnection;
use SineMacula\Laravel\Iam\Mfa\CurrentSession;
use SineMacula\Laravel\Iam\Transactions\AfterConnectionCommits;

/**
 * Applies a change of a tenant's authentication policy to the sessions acting
 * in it with the strict cut-off `laravel-authentication`'s
 * `tenantPolicyChanged()` asks for (IAM-4.5): once inside the transaction that
 * publishes the change, and once more after that transaction commits.
 *
 * The first pass runs at once, as a savepoint of the transaction open on
 * `laravel-authentication`'s storage connection, so it commits or rolls back
 * with the change. It locks only the sessions committed by then: a session that
 * enters the tenant while it runs (a password or passkey sign-in, a switch into
 * the tenant), having judged the policy as it was, is not among them. So the
 * second pass is held for the commit of the innermost transaction open on that
 * connection (`AfterConnectionCommits`), never another connection's: it reads
 * what is committed, judges such a session too, and skips every session the
 * first pass recorded at the version it answered. It runs once every callback
 * queued on the transaction has run; when one of those fails, the change
 * already durable, it runs as the request, the command or the job ends instead.
 * A rollback of the change drops it. With no transaction open, both passes run
 * at once.
 *
 * Every change of one tenant's policy the application reports itself goes
 * through here, of its tenant MFA requirement and of its SSO exemptions
 * (`Iam::tenantPolicies()->changed($tenant)`). A change that may reach a whole
 * subtree, SSO's enforcement changes through the session revocation
 * (`SessionRevocationAdapter`) and the application's reported tree moves, makes
 * the same two passes through `SubtreePolicyChanges`, whose pass after the
 * commit lists the subtree again rather than judge the tenants its first pass
 * listed. The passes go through `laravel-authentication`'s session service for
 * a change to the identity as a whole (`CurrentSession::identitySessions()`),
 * which ends the sessions of every guard alike. What either pass throws
 * propagates: the first from this call, inside the change's transaction, so it
 * rolls back; the second from the commit, the change already durable. Stateless
 * (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final readonly class TenantPolicyChanges
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Iam\Mfa\CurrentSession  $sessions
     * @param  \Illuminate\Database\DatabaseManager  $database
     * @param  \SineMacula\Laravel\Iam\Transactions\AfterConnectionCommits  $afterCommit
     */
    public function __construct(

        /** Resolves the session service both passes go through. */
        private CurrentSession $sessions,

        /** Resolves the storage connection whose commit the second pass waits for. */
        private DatabaseManager $database,

        /** Holds the second pass for that connection's own transaction. */
        private AfterConnectionCommits $afterCommit,
    ) {}

    /**
     * Judge the tenant's sessions against its policy as it now answers, in
     * place, and once more once the transaction open on the storage connection
     * commits; answer how many sessions the first pass revoked.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException
     * @throws \Throwable
     */
    public function changed(Tenant $tenant): int
    {
        $revoked = $this->sessions->identitySessions()->tenantPolicyChanged($tenant);

        $this->afterCommit->run($this->database->connection(StorageConnection::name()), function () use ($tenant): void {

            $this->sessions->identitySessions()->tenantPolicyChanged($tenant);
        });

        return $revoked;
    }
}
