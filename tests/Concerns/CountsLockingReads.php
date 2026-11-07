<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Database\StorageConnection;

/**
 * Asks a question while a transaction on the storage connection holds a
 * session's row locked, as `laravel-authentication` asks the tenant
 * authentication policy on a refresh, a switch, an external re-authentication
 * and `tenantPolicyChanged()`, or outside any transaction, and answers the
 * locking reads the question made itself: every statement run from the moment
 * the session's own lock was taken (or the question was asked) until the
 * question returned that reads `for update`, `for share`, `for no key update`,
 * `for key share` or `lock in share mode`.
 *
 * The one lock `laravel-authentication`'s order admits under the session's is a
 * shared lock of its proofs or provenance, which its own current reads take on
 * MySQL and MariaDB only (`SessionProofs`): `provenanceLocks()` answers the
 * locking reads such a current read of the session's provenance makes on the
 * engine the test runs on.
 *
 * Only MySQL and PostgreSQL write a lock into the statement, so a test using it
 * runs with `RunsAtIsolationLevels` and is skipped on SQLite.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \Tests\TestCase
 */
trait CountsLockingReads
{
    /**
     * Lock the session's row in a transaction on the storage connection, ask
     * the question inside it, and answer what the question answered and the
     * locking reads it made, once the transaction commits.
     *
     * @template TAnswer
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \Closure(): TAnswer  $question
     * @return array{0: TAnswer, 1: list<string>}
     *
     * @throws \Throwable
     */
    protected function askedUnderTheSessionsLock(EloquentSession&Model $session, \Closure $question): array
    {
        $locking = self::recordLockingReads();

        return DB::connection(StorageConnection::name())->transaction(static function () use ($session, $question, $locking): array {

            $session->newQuery()->whereKey($session->getKey())->lockForUpdate()->first();

            self::assertCount(1, $locking, 'The session\'s own lock was not seen, so no lock the question takes would be.');

            $before = count($locking);
            $answer = $question();

            return [$answer, array_slice($locking->getArrayCopy(), $before)];
        });
    }

    /**
     * Ask the question outside any transaction, and answer what it answered and
     * the locking reads it made.
     *
     * @template TAnswer
     *
     * @param  \Closure(): TAnswer  $question
     * @return array{0: TAnswer, 1: list<string>}
     */
    protected static function askedOutsideATransaction(\Closure $question): array
    {
        self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel(), 'The question was asked inside a transaction.');

        $locking = self::recordLockingReads();
        $answer  = $question();

        return [$answer, array_values($locking->getArrayCopy())];
    }

    /**
     * The locking reads a current read of the session's provenance makes on the
     * engine the test runs on: a shared lock of its row on MySQL and MariaDB,
     * and none on PostgreSQL, whose statements read what is committed.
     *
     * @return list<string>
     */
    protected static function provenanceLocks(): array
    {
        $connection = DB::connection(StorageConnection::name());

        if (!in_array($connection->getDriverName(), ['mysql', 'mariadb'], true)) {
            return [];
        }

        return [$connection->table('authentication_provenance')->where('authentication_provenance.session_id', '?')->limit(1)->sharedLock()->select('connection_id')->toSql()];
    }

    /**
     * Record every locking read run from now on.
     *
     * @return \ArrayObject<int, string>
     */
    private static function recordLockingReads(): \ArrayObject
    {
        /** @var \ArrayObject<int, string> $locking */
        $locking = new \ArrayObject;

        DB::listen(static function (QueryExecuted $query) use ($locking): void {
            if (preg_match('/\bfor (update|share|no key update|key share)\b|\block in share mode\b/i', $query->sql) !== 1) {
                return;
            }

            $locking->append($query->sql);
        });

        return $locking;
    }
}
