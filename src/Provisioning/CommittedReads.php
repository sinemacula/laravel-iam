<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Provisioning;

use Illuminate\Database\DatabaseManager;
use SineMacula\Laravel\Iam\Storage\StorageConnection;

/**
 * Has the provisioning listener's one attempt read what other transactions have
 * committed, and take no gap locks, on PostgreSQL, MySQL and MariaDB, whatever
 * isolation level the storage connection runs at (IAM-7.1, IAM-11.2).
 *
 * The listener cannot retry, since the grant allows one use, so any failure a
 * concurrent sign-in can cause it ends that sign-in as a server error. At
 * PostgreSQL's REPEATABLE READ, a transaction that locks a row another
 * transaction changed and committed after its snapshot began fails to serialise
 * (`40001`): every link SSO makes raises its connection's links version, so any
 * link committed in the connection while the listener runs, another person's
 * first sign-in included, would fail the listener's locking read of the
 * connection. At InnoDB's REPEATABLE READ, a locking read that finds no row
 * takes a gap lock on the index it searched: SSO's scope widening reads the new
 * identity's links by identity under a lock, finds none, and gap-locks the
 * links' identity index, before SSO's provisioning helper takes the enforcing
 * tenant's rule and the connection and inserts the link into that index. Gap
 * locks never conflict with each other, but each blocks the other transaction's
 * insert, so two first sign-ins whose identities fall in the same gap, or a
 * first sign-in and a link or reservation made for an existing identity there,
 * deadlock: each holds the links' gap before the connection, which inverts
 * SSO's lock order.
 *
 * At READ COMMITTED the locking reads wait for the other transaction's commit
 * and read what it committed, and InnoDB takes no gap locks for them; SSO's
 * provisioning helper re-reads the connection, the request and the links under
 * its own locks, so the competing link of the same subject is refused
 * `subject_already_linked` and another subject's leaves the provisioning
 * unaffected. So nothing is lost by it. SQLite, which writes one transaction at
 * a time, is left as it is. On MySQL, READ COMMITTED needs row-based binary
 * logging where the binary log is on, as MySQL 8's default `binlog_format`
 * gives; MariaDB's default mixed format switches to rows for it.
 *
 * The level is set only for a transaction the listener itself opens: inside one
 * a caller opened, the work runs in a savepoint and keeps the caller's level.
 * The engines take it at different moments. MySQL and MariaDB refuse to change
 * it inside an open transaction and apply `SET TRANSACTION` to the next one the
 * session begins, so it is set before the listener's transaction begins, with
 * none open (`beforeBeginning()`); PostgreSQL takes it only inside a
 * transaction, before its first statement, so it is set first in the listener's
 * work (`onceBegun()`). Stateless (IAM-8.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CommittedReads
{
    /** @var string The statement that sets the isolation level of the transaction it is given for. */
    public const string STATEMENT = 'set transaction isolation level read committed';

    /** @var list<string> The drivers whose next transaction is set before it begins, with none open. */
    private const array BEFORE_BEGINNING = ['mysql', 'mariadb'];

    /** @var string The driver whose transaction is set once begun, before its first statement. */
    private const string ONCE_BEGUN = 'pgsql';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Database\DatabaseManager  $database
     * @param  \SineMacula\Laravel\Iam\Storage\StorageConnection  $storage
     */
    public function __construct(

        /** The connections the listener's transaction runs on. */
        private DatabaseManager $database,

        /** The storage connection's name. */
        private StorageConnection $storage,
    ) {}

    /**
     * Set the next transaction the storage connection begins to READ COMMITTED,
     * on MySQL and MariaDB, while no transaction is open there: the one the
     * listener is about to begin. Inside a caller's transaction nothing is set,
     * since the listener's work runs in a savepoint of it.
     *
     * @return void
     */
    public function beforeBeginning(): void
    {
        $connection = $this->database->connection($this->storage->name());

        if (!in_array($connection->getDriverName(), self::BEFORE_BEGINNING, true) || $connection->transactionLevel() !== 0) {
            return;
        }

        $connection->statement(self::STATEMENT);
    }

    /**
     * Set the transaction just begun on the storage connection, the outermost
     * one with nothing yet run in it, to READ COMMITTED, on PostgreSQL. Inside
     * a caller's transaction nothing is set.
     *
     * @return void
     */
    public function onceBegun(): void
    {
        $connection = $this->database->connection($this->storage->name());

        if ($connection->getDriverName() !== self::ONCE_BEGUN || $connection->transactionLevel() !== 1) {
            return;
        }

        $connection->statement(self::STATEMENT);
    }
}
