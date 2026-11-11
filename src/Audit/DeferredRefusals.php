<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Audit;

use Illuminate\Container\Container;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Iam\Transactions\ConnectionTransactions;

/**
 * Holds the refusals and decisions reported inside a transaction on audit-log's
 * storage connection until that transaction ends, so a rollback cannot take
 * their records with it (IAM-9.5).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class DeferredRefusals
{
    /** @var list<\SineMacula\Laravel\Authentication\Events\AuthenticationFailed|\SineMacula\Laravel\Authorization\Events\DecisionEvaluated> */
    private array $held = [];

    /**
     * Whether the event is held until the transactions open on the storage
     * connection end.
     *
     * @param  object  $event
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function defers(#[\SensitiveParameter] object $event): bool
    {
        // Without a transactions manager no transaction can be waited on.
        $isRefusal = $event instanceof AuthenticationFailed || $event instanceof DecisionEvaluated;
        $open      = $isRefusal && Container::getInstance()->bound('db.transactions') ? ConnectionTransactions::open(StorageConnection::name()) : [];

        if ($open === []) {
            return false;
        }

        $this->held[] = $event;

        $this->waitFor($open);

        return true;
    }

    /**
     * Release the refusals held when any open transaction rolls back, or once
     * the outermost commits.
     *
     * Every open transaction is waited on, since Laravel 12 does not tell a
     * committed savepoint of its parent's rollback.
     *
     * @param  list<\Illuminate\Database\DatabaseTransactionRecord>  $open
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function waitFor(array $open): void
    {
        $release = function (): void {

            $this->release();
        };

        foreach ($open as $transaction) {
            $transaction->addCallbackForRollback($release);
        }

        ConnectionTransactions::afterCommit(StorageConnection::name(), $release);
    }

    /**
     * Hand each refusal held to the recorder's capture, which holds it again
     * while a transaction is still open.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Database\DeadlockException
     * @throws \RuntimeException
     */
    private function release(): void
    {
        $held       = $this->held;
        $this->held = [];
        $recorder   = Container::getInstance()->make(Recorder::class);

        foreach ($held as $refusal) {
            $recorder->capture($refusal);
        }
    }
}
