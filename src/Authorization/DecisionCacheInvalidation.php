<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Authorization;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Evaluation\LastDecisionStore;
use SineMacula\Laravel\Authorization\Evaluation\RequirementFreshness;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Iam\Transactions\OpenTransactions;
use SineMacula\Laravel\Mfa\Database\StorageConnection;

/**
 * Forgets the decision `laravel-authorization` keeps that depended on an
 * identity's authentication once that authentication changes (IAM-6.11,
 * AUTHZ-12.3): called by this package's MFA adapters, never from a listener,
 * when a factor is confirmed or removed, a passkey registered, an identity's
 * factors reset, a verification passes, or a session returns to pending.
 *
 * `laravel-authorization` caches grant resolutions, never decisions: each check
 * decides afresh, so a later check always reads the session's proofs as they
 * are. The one decision it keeps is the request's or the job's last
 * (`Authorization::lastDecision()`, held in its scoped `LastDecisionStore`),
 * which it drops once a met requirement it read stops being met (`metUntil`),
 * but not when the session's proofs change within the same request or job: a
 * factor removed after a check allowed through a multifactor requirement would
 * still leave that allow as the last decision. So the last decision is
 * forgotten here when it read an authentication requirement (it carries a
 * `RequirementFreshness`) and either was made in the session named, compared as
 * `laravel-authorization` compares it, by fingerprint, but whether or not a met
 * requirement it read has since lapsed (`Decision::isFreshFor()` would also ask
 * that, and so keep a decision whose requirement lapsed between reading it and
 * comparing it), or was about the identity, by its morph class and key: a
 * change to an identity's factors can change the requirement any of its
 * sessions meets. A decision that read no requirement depends on no proof, and
 * is kept, as is one about another identity made in another session.
 *
 * It is called inside MFA's transaction, as its adapters are. The last decision
 * is forgotten at once, so a check made after the change, in the same
 * transaction, reads the new proofs; and again should any transaction open on
 * the storage connection roll back, since a check made between the change and
 * the rollback read proofs that were never committed. The second pass waits on
 * every transaction open there that Laravel's transactions manager lets
 * callbacks apply to (`Transactions\OpenTransactions`), not only the innermost,
 * as the audit trail's deferred refusals wait (`Audit\DeferredRefusals`): not
 * every version of Laravel tells a savepoint that has committed of its
 * enclosing transaction's rollback, so MFA's own transaction, a savepoint of
 * the caller's that commits, would otherwise leave the decision standing once
 * the caller's rolls back. A commit needs no second pass: a check made after
 * the change read what committed.
 *
 * Glue, not policy: whether a decision depends on authentication is what
 * `laravel-authorization` records on it. The store, the connection and the
 * transactions open are resolved on every call, never kept, so a request's or a
 * job's own store, an Octane request's sandbox included, is the one emptied
 * (IAM-8.1).
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

        /** Resolves `laravel-authorization`'s store of the last decision, the current request's or job's. */
        private Container $container,

        /** Resolves the storage connection whose rollback forgets again. */
        private DatabaseManager $database,
    ) {}

    /**
     * Forget the last decision when it read an authentication requirement and
     * was made in the session given, or was about the identity, at once and
     * again should any transaction open on the storage connection roll back.
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
        $about = $identity instanceof Model ? Reference::of($identity) : null;

        $this->forget($about, $session);

        $manager = OpenTransactions::manager();

        if ($manager === null) {
            return;
        }

        $again = function () use ($about, $session): void {
            $this->forget($about, $session);
        };

        foreach (OpenTransactions::on($manager, $this->database->connection(StorageConnection::name())) as $transaction) {
            $transaction->addCallbackForRollback($again);
        }
    }

    /**
     * Forget the last decision when it read an authentication requirement and
     * was made in the session, or was about the identity.
     *
     * @param  ?\SineMacula\Laravel\Authorization\Support\Reference  $about
     * @param  ?string  $session
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function forget(?Reference $about, ?string $session): void
    {
        $store    = $this->container->make(LastDecisionStore::class);
        $decision = $store->get();

        if ($decision?->freshness === null) {
            return;
        }

        $inSession = $session !== null && (new RequirementFreshness($session))->session === $decision->freshness->session;

        if (!$inSession && !self::isAbout($store->provenanceOf($decision)?->identity, $about)) {
            return;
        }

        $store->forget();
    }

    /**
     * Whether the decision's identity is the one the change was made to.
     *
     * @param  ?\SineMacula\Laravel\Authorization\Support\Reference  $held
     * @param  ?\SineMacula\Laravel\Authorization\Support\Reference  $about
     * @return bool
     */
    private static function isAbout(?Reference $held, ?Reference $about): bool
    {
        return $held !== null && $about !== null && $held->type === $about->type && $held->id === $about->id;
    }
}
