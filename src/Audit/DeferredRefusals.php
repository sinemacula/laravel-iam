<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Audit;

use Illuminate\Container\Container;
use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\DatabaseTransactionRecord;
use Illuminate\Database\DatabaseTransactionsManager;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Iam\Transactions\AfterConnectionCommits;

/**
 * The refusals `laravel-authentication` reports while a transaction is open on
 * audit-log's storage connection, held until the outermost transaction there
 * has ended, whichever way it ended, and recorded then (IAM-9.5).
 *
 * `laravel-authentication` dispatches `AuthenticationFailed` at once, never
 * after a commit, from inside whatever transaction its caller opened: this
 * package's redemption of an SSO code, which rolls back by throwing so the code
 * stays unspent (`SignInRedemption`, `ReauthenticationRedemption`); MFA's
 * step-up and pending completion, whose adapters throw on a refusal so MFA
 * rolls its verification back (`StepUpAdapter`, `PendingCompletionAdapter`);
 * MFA's enrolment, which rolls back when its first code is refused; and any
 * transaction the application opened. Audit-log writes a captured record at
 * once, so with its storage on the storage connection, as IAM-9.9's read
 * refusal needs, the refusal's record would roll back with any of them, and the
 * refusal, with `laravel-authentication`'s own reason, would be left
 * unrecorded.
 *
 * So the authentication mapper hands this every `AuthenticationFailed` it meets
 * (`defers()`). With no transaction open on the storage connection it holds
 * nothing, and the refusal is recorded at once. Otherwise it holds the refusal,
 * the mapper records nothing of it, and it waits for the transactions open
 * there to end: a rollback of any of them releases it at once (a rollback
 * callback of each, since not every version of Laravel tells a savepoint that
 * has committed of its enclosing transaction's rollback); a commit, once the
 * outermost transaction there has committed and every callback queued on it has
 * run (`AfterConnectionCommits`, released by Laravel's `TransactionCommitted`).
 * A release hands each refusal held, the same object, in the order reported, to
 * audit-log's capture, where the mapper hands it here again: while a
 * transaction is still open there (a savepoint rolled back inside another) it
 * is held again, waiting for those still open, and once none is, the mapper
 * describes it from the event alone, as any other refusal. Audit-log never
 * claimed the object, so it is captured then, once, however audit-log stores,
 * and never inside a transaction that may still roll back. A refusal reported
 * by an attempt the retry helper ran again is recorded as well, since it
 * reached every other listener too.
 *
 * The transactions open are those Laravel's transactions manager lets callbacks
 * apply to, so the transaction a testing trait wraps a test in is none, and of
 * those only the ones the connection still has open, since inside the rollback
 * of the outermost the manager still lists it.
 *
 * It is bound scoped, under this package's own key for scoped adapters, so it
 * holds one request's or one job's refusals alone, and the worker reset forgets
 * it (IAM-8.1); a transaction's callbacks keep the instance that held its
 * refusals, and resolve the recorder from the application current when they
 * run.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class DeferredRefusals
{
    /** @var string The container key Laravel binds its transactions manager under. */
    private const string MANAGER = 'db.transactions';

    /** @var list<\SineMacula\Laravel\Authentication\Events\AuthenticationFailed> The refusals held until the transactions open have ended, in the order they were reported. */
    private array $held = [];

    /**
     * Whether the event is a refusal held until the transactions open on the
     * storage connection have ended, to be recorded then: `false`, holding
     * nothing, for any other event, when no transaction is open there, and
     * while the application holds no transactions manager.
     *
     * @param  object  $event
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function defers(#[\SensitiveParameter] object $event): bool
    {
        $manager = $event instanceof AuthenticationFailed ? self::manager() : null;

        if ($manager === null) {
            return false;
        }

        $storage = Container::getInstance()->make(DatabaseManager::class)->connection(StorageConnection::name());
        $open    = self::open($manager, $storage);

        if ($open === []) {
            return false;
        }

        $this->held[] = $event;

        $this->waitFor($storage, $open);

        return true;
    }

    /**
     * Release the refusals held once the transactions open end: at once when
     * any of them rolls back, and once the outermost has committed when they
     * commit.
     *
     * The rollback is waited for on every transaction open, not only the
     * innermost, since a savepoint that has committed is not told of its
     * enclosing transaction's rollback by every version of Laravel.
     *
     * @param  \Illuminate\Database\Connection  $storage
     * @param  array<int, \Illuminate\Database\DatabaseTransactionRecord>  $open
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function waitFor(Connection $storage, array $open): void
    {
        $release = function (): void {

            $this->release();
        };

        foreach ($open as $transaction) {
            $transaction->addCallbackForRollback($release);
        }

        Container::getInstance()->make(AfterConnectionCommits::class)->run($storage, $release);
    }

    /**
     * Hand each refusal held, in order, to the recorder's capture, holding none
     * any more: a refusal reported while a transaction is still open (a
     * savepoint rolled back inside another) is held again as it is captured,
     * and waits for those still open, and any other is recorded.
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

    /**
     * The transactions manager the application holds, or `null` for none,
     * without which no transaction's end could be waited for.
     *
     * @return ?\Illuminate\Database\DatabaseTransactionsManager
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private static function manager(): ?DatabaseTransactionsManager
    {
        $container = Container::getInstance();
        $manager   = $container->bound(self::MANAGER) ? $container->make(self::MANAGER) : null;

        return $manager instanceof DatabaseTransactionsManager ? $manager : null;
    }

    /**
     * The transactions the manager lets callbacks apply to that are still open
     * on the connection, outermost first.
     *
     * @param  \Illuminate\Database\DatabaseTransactionsManager  $manager
     * @param  \Illuminate\Database\Connection  $storage
     * @return array<int, \Illuminate\Database\DatabaseTransactionRecord>
     */
    private static function open(DatabaseTransactionsManager $manager, Connection $storage): array
    {
        $name  = $storage->getName();
        $level = $storage->transactionLevel();

        return $manager->callbackApplicableTransactions()
            ->filter(static fn (DatabaseTransactionRecord $transaction): bool => $transaction->connection === $name && $transaction->level <= $level)
            ->all();
    }
}
