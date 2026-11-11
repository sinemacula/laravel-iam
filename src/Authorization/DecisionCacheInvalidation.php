<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Authorization;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Iam\Transactions\ConnectionTransactions;
use SineMacula\Laravel\Mfa\Database\StorageConnection;

/**
 * Has `laravel-authorization` forget the request's decisions once an identity's
 * authentication changes (IAM-6.11, AUTHZ-12.3).
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
     */
    public function __construct(

        /** Resolves `laravel-authorization`'s manager, the current request's or job's. */
        private Container $container,
    ) {}

    /**
     * Forget the decisions at once, and again if a transaction open on the
     * storage connection rolls back.
     *
     * Every open transaction is waited on, since Laravel 12 does not tell a
     * committed savepoint of its parent's rollback.
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

        $again = function () use ($identity, $session): void {
            $this->forget($identity, $session);
        };

        foreach (ConnectionTransactions::open(StorageConnection::name()) as $transaction) {
            $transaction->addCallbackForRollback($again);
        }
    }

    /**
     * Have `laravel-authorization` forget the decisions, naming the session and
     * identity whose authentication changed.
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
