<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\Connection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;

/**
 * Looks at a session's row from a second connection to the test's database,
 * outside the test's transactions, to tell whether the test's own transaction
 * holds a lock on it, without ever waiting long on that lock.
 *
 * Only MySQL and PostgreSQL have row locks to look for, so a test using it runs
 * with `RunsAtIsolationLevels` and is skipped on SQLite.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \Tests\TestCase
 */
trait FindsLockedSessions
{
    /** @var string The second connection the lock and race cases look from. */
    private const string OTHER = 'other';

    /**
     * Whether another connection finds the session's row locked.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return bool
     */
    protected function isLockedElsewhere(EloquentSession&Model $session): bool
    {
        $other = $this->other();

        $other->beginTransaction();

        $lock = static fn (): mixed => $other->table($session->getTable())->where($session->getKeyName(), $session->getKey())->lock('for update nowait')->first();

        try {
            $lock();

            return false;
        } catch (QueryException) {
            return true;
        } finally {
            $other->rollBack();
        }
    }

    /**
     * A second connection to the test's database, outside its transactions.
     *
     * @return \Illuminate\Database\Connection
     */
    protected function other(): Connection
    {
        Config::set('database.connections.' . self::OTHER, Config::get('database.connections.' . self::CONNECTION));

        $other = DB::connection(self::OTHER);

        // Never wait long on a lock the test's own transaction holds.
        $other->statement($other->getDriverName() === 'pgsql' ? 'set lock_timeout = \'5s\'' : 'set session innodb_lock_wait_timeout = 5');

        return $other;
    }
}
