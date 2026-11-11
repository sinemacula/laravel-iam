<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Authorization;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\DatabaseManager;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Iam\Transactions\OpenTransactions;
use SineMacula\Laravel\Mfa\Database\StorageConnection;

/**
 * Has `laravel-authorization` forget the decisions of the request or job once
 * an identity's authentication changes (IAM-6.11, AUTHZ-12.3): called by this
 * package's MFA adapters, never from a listener, when a factor is confirmed or
 * removed, a passkey registered, an identity's factors reset, a verification
 * passes, or a session returns to pending; and by the SSO reauthentication
 * redemption once it has renewed the session its code names.
 *
 * `laravel-authorization` keeps, for the request or job, the last decision
 * (`Authorization::lastDecision()`), the subject and tenant it resolved, its
 * resolution memo and what a running batch of checks has read ahead, none of
 * which it drops when the session's proofs change within the request or job.
 * Its `forgetDecisionsFor()` forgets all of it, whatever the session and the
 * identity named, so the rest of the request or job decides afresh on the new
 * proofs; it leaves the persistent resolution cache alone, since no grant
 * changed, and never refuses. The session and the identity are handed on as
 * naming the change, for the reader and for a version that forgets selectively.
 *
 * It is called inside the transaction the change is made in, as the adapters
 * are. The decisions are forgotten at once, so a check made after the change,
 * in the same transaction, reads the new proofs; and again should any
 * transaction open on the storage connection roll back, since a check made
 * between the change and the rollback read proofs that were never committed.
 * That second pass is this package's, as `laravel-authorization` knows nothing
 * of the transaction: it waits on every transaction open there that Laravel's
 * transactions manager lets callbacks apply to
 * (`Transactions\OpenTransactions`), not only the innermost, as the audit
 * trail's deferred refusals wait (`Audit\DeferredRefusals`): not every version
 * of Laravel tells a savepoint that has committed of its enclosing
 * transaction's rollback, so MFA's own transaction, a savepoint of the caller's
 * that commits, would otherwise leave the decisions standing once the caller's
 * rolls back. A commit needs no second pass: a check made after the change read
 * what committed.
 *
 * Glue, not policy: what is forgotten is `laravel-authorization`'s to say. The
 * manager, the connection and the transactions open are resolved on every call,
 * never kept, so a request's or a job's own manager, an Octane request's
 * sandbox included, is the one that forgets (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class DecisionCacheInvalidation
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Database\DatabaseManager  $database
     */
    public function __construct(

        /** Resolves `laravel-authorization`'s manager, the current request's or job's. */
        private Container $container,

        /** Resolves the storage connection whose rollback forgets again. */
        private DatabaseManager $database,
    ) {}

    /**
     * Forget the decisions of the request or job, the identity's authentication
     * having changed, in the session given if any, at once and again should any
     * transaction open on the storage connection roll back.
     *
     * @param  object  $identity
     * @param  ?string  $session
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function authenticationChanged(object $identity, ?string $session = null): void
    {
        $this->forget($identity, $session);

        $manager = OpenTransactions::manager();

        if ($manager === null) {
            return;
        }

        $again = function () use ($identity, $session): void {
            $this->forget($identity, $session);
        };

        foreach (OpenTransactions::on($manager, $this->database->connection(StorageConnection::name())) as $transaction) {
            $transaction->addCallbackForRollback($again);
        }
    }

    /**
     * Have `laravel-authorization` forget the decisions of the request or job,
     * naming the session and the identity whose authentication changed.
     *
     * @param  object  $identity
     * @param  ?string  $session
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function forget(object $identity, ?string $session): void
    {
        $this->container->make(AuthorizationManager::class)->forgetDecisionsFor(session: $session, identity: $identity);
    }
}
