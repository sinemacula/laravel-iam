<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;

/**
 * Signs a person in with their password in the tenant on another connection to
 * the same database while a change of the tenant's policy runs its first
 * `tenantPolicyChanged()` pass, against the strict cut-off
 * `laravel-authentication` asks for: the sign-in judges the tenant's policy as
 * it was before the change, and its session is not among the rows the first
 * pass locked.
 *
 * On PostgreSQL at either isolation level and on MySQL at READ COMMITTED the
 * sign-in commits after the change's first pass and before the change commits,
 * the first pass's locks holding no row it writes. On MySQL at REPEATABLE READ
 * the first pass's locking read holds the gap the session's row would go in, so
 * the sign-in's write waits for the change to commit and then goes ahead with
 * the verdict it made: the sign-in commits once the change has, before the
 * second pass runs.
 *
 * The test using it rolls back what is left open on the other connection as it
 * tears down (`rollBackElsewhere()`), so the migrations' rollback never waits
 * on it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait SignsInDuringTheFirstPass
{
    /** @var string The second connection the sign-in is made on. */
    private const string ELSEWHERE = 'elsewhere';

    /**
     * Roll back what is left open on the other connection.
     *
     * @return void
     */
    private function rollBackElsewhere(): void
    {
        $elsewhere = $this->app?->make('db')->getConnections()[self::ELSEWHERE] ?? null;

        while ($elsewhere !== null && $elsewhere->transactionLevel() > 0) {
            $elsewhere->rollBack();
        }
    }

    /**
     * Sign the person in with their password on the guard, acting in the
     * tenant, inside the transaction open on the other connection, made the
     * default (and so every member's storage connection) while it runs, and
     * commit that transaction; answer the session's key.
     *
     * @param  string  $email
     * @return string
     *
     * @throws \Throwable
     */
    private function signInElsewhere(string $email): string
    {
        $default   = DB::getDefaultConnection();
        $elsewhere = DB::connection(self::ELSEWHERE);

        DB::setDefaultConnection(self::ELSEWHERE);

        try {
            $context = new SignInContext(self::client(), tenant: TenantSelection::of(self::TENANT));
            $result  = $this->sessions()->signIn('password', ['email' => $email, 'password' => self::PASSWORD], $context);

            self::assertTrue($result->isSignedIn(), (string) $result->reason?->value);

            $elsewhere->commit();

            return self::keyOf($result->session->record ?? self::fail('The sign-in established no session.'));
        } finally {
            while ($elsewhere->transactionLevel() > 0) {
                $elsewhere->rollBack();
            }

            DB::setDefaultConnection($default);
        }
    }

    /**
     * Once the change's first pass has read the keys of the tenant's live
     * sessions with its locking read, inside the change's transaction, open a
     * transaction on the other connection at the level and read in it, so the
     * sign-in judges the tenant's policy as it was before the change, and run
     * the sign-in: at once, or on MySQL at REPEATABLE READ, where the first
     * pass's gap lock holds the sign-in's write until the change commits, as
     * the first of the change's commit callbacks, before the second pass.
     *
     * @param  string  $level
     * @param  \Closure(): void  $signIn
     * @return void
     */
    private function onceTheFirstPassHasRead(string $level, \Closure $signIn): void
    {
        Config::set('database.connections.' . self::ELSEWHERE, Config::get('database.connections.' . self::CONNECTION));

        $elsewhere = DB::connection(self::ELSEWHERE);

        // Never wait long on a lock the change holds.
        $elsewhere->statement($elsewhere->getDriverName() === 'pgsql' ? 'set lock_timeout = \'5s\'' : 'set session innodb_lock_wait_timeout = 5');

        self::useIsolationLevel($level, self::ELSEWHERE);

        self::onTheFirstPass(static function (QueryExecuted $query) use ($level, $signIn, $elsewhere): void {

            $deferred = $query->connection->getDriverName() === 'mysql' && $level === 'repeatable read';

            // Queued before the other connection's transaction opens, so it is
            // queued on the change's own.
            if ($deferred) {
                $query->connection->afterCommit($signIn);
            }

            $elsewhere->beginTransaction();
            $elsewhere->table('authentication_sessions')->count();

            if ($deferred) {
                return;
            }

            $signIn();
        });
    }

    /**
     * Run the callback once, as the first pass of a change of the tenant's
     * policy makes its locking read of the keys of the tenant's live sessions,
     * on the test's connection inside the change's transaction.
     *
     * @param  \Closure(\Illuminate\Database\Events\QueryExecuted): void  $then
     * @return void
     */
    private static function onTheFirstPass(\Closure $then): void
    {
        $ran = false;

        DB::connection(self::CONNECTION)->listen(static function (QueryExecuted $query) use (&$ran, $then): void {

            if ($ran || !self::isTheFirstPass($query)) {
                return;
            }

            $ran = true;

            $then($query);
        });
    }

    /**
     * Whether the query is the first pass's locking read of the keys of the
     * tenant's live sessions, made on the test's connection inside the change's
     * transaction.
     *
     * @param  \Illuminate\Database\Events\QueryExecuted  $query
     * @return bool
     */
    private static function isTheFirstPass(QueryExecuted $query): bool
    {
        $sql = strtolower($query->sql);

        return $query->connectionName === self::CONNECTION
            && $query->connection->transactionLevel() > 0
            && str_contains($sql, 'authentication_sessions')
            && str_contains($sql, 'tenant_id')
            && str_contains($sql, 'for update');
    }
}
