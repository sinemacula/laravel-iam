<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\Connection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use Tests\Fixtures\Models\Person;

/**
 * Asks an adapter inside a caller's transaction on the storage connection after
 * another connection to the test's database has committed a change to the
 * session's proofs, as another request would while the caller's request runs.
 *
 * The caller's transaction makes a plain read first, so on MySQL at REPEATABLE
 * READ its snapshot predates the change and only a read made current (the
 * session's row locked, its proofs read with a shared lock) sees it; at READ
 * COMMITTED every read sees it. On PostgreSQL at REPEATABLE READ no read sees
 * past the snapshot, so locking the session's row the change wrote fails to
 * serialise instead, and the question is asked again in a new transaction, as a
 * caller retrying the whole of it would. The change is made through
 * `laravel-authentication`'s public session service on the other connection, so
 * it writes what a real one writes, the session's row included.
 *
 * It is used with `SignsInPeople`, `MigratesMembers` and
 * `RunsAtIsolationLevels`, by tests that run only where isolation levels do
 * (never on SQLite, whose in-memory database each connection would have to
 * itself).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \Tests\TestCase
 */
trait ChangesSessionsElsewhere
{
    /**
     * Open the caller's transaction, read plainly, run the change on the other
     * connection, then ask the question inside the caller's transaction, once
     * more in a new one when the first fails to serialise (PostgreSQL at
     * REPEATABLE READ only), and return the answer once the transaction
     * commits.
     *
     * @param  string  $level
     * @param  \Closure(): mixed  $change
     * @param  \Closure(): mixed  $question
     * @return mixed
     *
     * @throws \Throwable
     */
    protected function askedAfter(string $level, \Closure $change, \Closure $question): mixed
    {
        $storage = self::callerConnection();

        try {
            $storage->beginTransaction();

            self::assertGreaterThan(0, $storage->table('authentication_proofs')->count());

            $change();

            if (self::readsASnapshot($storage, $level)) {

                self::assertFailsToSerialise($question);

                $storage->rollBack();
                $storage->beginTransaction();
            }

            $answer = $question();

            $storage->commit();

            return $answer;
        } finally {
            while ($storage->transactionLevel() > 0) {
                $storage->rollBack();
            }
        }
    }

    /**
     * Run the work in a transaction on another connection to the test's
     * database, made the default (and so the storage connection) while it runs,
     * and committed before this returns.
     *
     * @param  \Closure(): mixed  $work
     * @return void
     *
     * @throws \Throwable
     */
    protected function elsewhere(\Closure $work): void
    {
        $elsewhere = 'elsewhere';

        Config::set('database.connections.' . $elsewhere, Config::get('database.connections.' . self::CONNECTION));

        $default = DB::getDefaultConnection();

        DB::setDefaultConnection($elsewhere);

        try {
            DB::transaction($work);
        } finally {
            DB::setDefaultConnection($default);
        }
    }

    /**
     * Remove the factor through `laravel-authentication` on another connection,
     * with the session as the one it is removed from, as MFA's removal does:
     * the session's row written, and its proofs made with the factor voided.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  string  $factor
     * @return void
     *
     * @throws \Throwable
     */
    protected function removeElsewhere(Person $person, EloquentSession&Model $session, string $factor): void
    {
        $this->elsewhere(function () use ($person, $session, $factor): void {

            $identity = Person::query()->findOrFail($person->getKey());
            $current  = Session::query()->findOrFail($session->getKey());

            $this->sessions()->factorRemoved($identity, $factor, $current);
        });
    }

    /**
     * Prove the person's password again on the session through
     * `laravel-authentication`, on another connection, failing the test unless
     * it is recorded.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return void
     *
     * @throws \Throwable
     */
    protected function reauthenticateElsewhere(Person $person, EloquentSession&Model $session): void
    {
        $this->elsewhere(function () use ($person, $session): void {

            $stored = Session::query()->findOrFail($session->getKey());
            $result = $this->sessions()->reauthenticate($stored, 'password', ['email' => $person->email, 'password' => self::PASSWORD], self::client());

            self::assertTrue($result->isIssued(), sprintf('The person did not reauthenticate: [%s].', $result->reason?->value));
        });
    }

    /**
     * The storage connection the caller's transaction, and every member's, runs
     * on.
     *
     * @return \Illuminate\Database\Connection
     */
    private static function callerConnection(): Connection
    {
        $connection = DB::connection(StorageConnection::name());

        self::assertInstanceOf(Connection::class, $connection);

        return $connection;
    }

    /**
     * Whether a transaction at the level reads one snapshot throughout, so a
     * lock on a row written since fails to serialise: PostgreSQL's at
     * REPEATABLE READ.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $level
     * @return bool
     */
    private static function readsASnapshot(Connection $connection, string $level): bool
    {
        return $connection->getDriverName() === 'pgsql' && $level === 'repeatable read';
    }

    /**
     * Assert the question fails to serialise (SQLSTATE `40001`, wherever it is
     * in the chain of the exception it throws).
     *
     * @param  \Closure(): mixed  $question
     * @return void
     *
     * @throws \Throwable
     */
    private static function assertFailsToSerialise(\Closure $question): void
    {
        try {
            $question();
        } catch (\Throwable $exception) {

            for ($failure = $exception; $failure !== null; $failure = $failure->getPrevious()) {
                if ((string) $failure->getCode() === '40001') {
                    return;
                }
            }

            throw $exception;
        }

        self::fail('The question did not fail to serialise.');
    }
}
