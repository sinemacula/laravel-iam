<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Authorization;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Events\Reauthenticated;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Iam\Transactions\ConnectionTransactions;
use SineMacula\Laravel\Mfa\Database\StorageConnection;

/**
 * Has `laravel-authorization` forget the request's decisions once an identity's
 * authentication changes.
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
     * Forget the decisions now, and again if a storage transaction rolls back.
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

        // Laravel 12 hides a parent's rollback from a committed savepoint.
        foreach (ConnectionTransactions::open(StorageConnection::name()) as $transaction) {
            $transaction->addCallbackForRollback($again);
        }
    }

    /**
     * Forget the decisions once a session's reauthentication has committed.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Reauthenticated  $event
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function reauthenticated(Reauthenticated $event): void
    {
        $this->forget(null, $event->context->sessionId);
    }

    /**
     * Have `laravel-authorization` forget the decisions.
     *
     * @param  ?object  $identity
     * @param  ?string  $session
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function forget(?object $identity, ?string $session): void
    {
        $this->container->make(AuthorizationManager::class)->forgetDecisionsFor(session: $session, identity: $identity);
    }
}
