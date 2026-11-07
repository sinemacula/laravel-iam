<?php

declare(strict_types = 1);

namespace Tests\Integration\Provisioning;

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Iam\Provisioning\CommittedReads;
use SineMacula\Laravel\Iam\Provisioning\ProvisioningSettings;
use SineMacula\Laravel\Iam\Provisioning\ProvisionOnUnlinkedResult;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken;
use Tests\Concerns\MigratesSso;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Provisioning\ProvisionedMembership;
use Tests\Fixtures\Provisioning\ProvisionsPeople;
use Tests\TestCase;

/**
 * Integration tests for two first sign-ins through one connection provisioned
 * at the same moment (IAM-7.1, IAM-11.2), on MySQL and PostgreSQL at READ
 * COMMITTED and REPEATABLE READ.
 *
 * The first sign-in's listener holds its transaction open once SSO's scope
 * widening has read the new person's links under a lock, and before SSO's
 * provisioning helper takes the connection, while a forked worker provisions
 * the second sign-in's person on a second connection to the same database, from
 * its start to its commit. At InnoDB's REPEATABLE READ that locking read, which
 * finds no link, would gap-lock the links' identity index: the worker's link
 * insert would wait on it while holding the connection the first listener then
 * locks, and one of the two would end as a deadlock, which the listener cannot
 * retry, since its grant allows one use. The listener's attempt reads committed
 * rows instead, which takes no gap lock, so the worker never waits on the first
 * listener, and both people are provisioned, each with a membership and a link
 * of `provisioning` origin.
 *
 * Each side stops at nothing but the other: the first listener goes on once the
 * worker has ended or waits on a lock, so a regression ends as the deadlock it
 * would be, rather than hanging. SQLite's single writer cannot hold two
 * transactions open, so it is not run there.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProvisionOnUnlinkedResult::class)]
#[CoversClass(CommittedReads::class)]
final class ConcurrentProvisioningTest extends TestCase
{
    use MigratesSso, RunsAtIsolationLevels, RunsSsoFlows, SignsInPeople;

    /** @var string The connection the forked worker provisions on. */
    private const string RACER = 'racer';

    /** @var string The connection the worker's lock wait is watched from. */
    private const string OBSERVER = 'observer';

    /** @var string The subject the worker's sign-in names, apart from the first's. */
    private const string OTHER_SUBJECT = 'other-subject';

    /** @var string What the worker reports once its sign-in was provisioned and handed off. */
    private const string PROVISIONED = 'provisioned';

    /** @var int How long the worker is watched for between polls, in microseconds. */
    private const int POLL_INTERVAL = 100000;

    /** @var int How many times the worker is polled for before the test fails. */
    private const int POLLS = 150;

    /** @var int How long either side waits for a line from the other, in seconds. */
    private const int WORKER_TIMEOUT = 30;

    /** @var int How long either side waits on a lock before giving up, in seconds. */
    private const int LOCK_TIMEOUT = 5;

    /** @var ?int The forked worker's process id, once forked. */
    private ?int $worker = null;

    /** @var resource|null The parent's end of the line to the worker, once forked. */
    private mixed $channel = null;

    /**
     * Arrange SSO on a database with isolation levels, and the connections the
     * worker provisions on and is watched from.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        self::requireIsolationLevels();
        self::requireAFork();

        $this->arrangeSso();

        Config::set('database.connections.' . self::RACER, Config::get('database.connections.' . self::CONNECTION));
        Config::set('database.connections.' . self::OBSERVER, Config::get('database.connections.' . self::CONNECTION));
    }

    /**
     * Reap the worker if a failure left it running.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->reap();

        parent::tearDown();
    }

    /**
     * Two people signing in through the connection for the first time at once
     * are both provisioned: the second, provisioned and committed while the
     * first's listener holds its transaction open past the widening, never
     * waits on the first, and the first then links its own person.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testTwoFirstSignInsAtOnceAreBothProvisioned(string $level): void
    {
        self::useIsolationLevel($level);
        self::waitBriefly(self::CONNECTION);

        $raced = false;

        $this->app?->instance(ProvisionsPeople::class, new ProvisionsPeople(function (string $step) use (&$raced, $level): void {

            if ($step !== 'membership' || $raced) {
                return;
            }

            $raced = true;

            $this->raceAnotherFirstSignIn($level);
        }));

        $this->app?->make('config')->set(ProvisioningSettings::KEY, ProvisionsPeople::class);

        $this->handoff();

        self::assertTrue($raced, 'The first sign-in was never provisioned.');
        self::assertSame(self::PROVISIONED, $this->workerOutcome());

        $people = Person::query()->orderBy('id')->get();

        self::assertCount(2, $people);

        foreach ($people as $person) {
            self::assertSame(LinkOrigin::PROVISIONING, Link::query()->where('identity_id', (string) $person->id)->sole()->provenance);
            self::assertSame([self::TENANT], ProvisionedMembership::query()->where('person_id', $person->id)->pluck('tenant_id')->all());
        }
    }

    /**
     * Skip a race that needs a second process where this one cannot fork.
     *
     * @return void
     */
    private static function requireAFork(): void
    {
        if (function_exists('pcntl_fork') && function_exists('posix_kill')) {
            return;
        }

        self::markTestSkipped('A race needs a process that can fork.');
    }

    /**
     * Have the connection given wait briefly on a lock before giving up, so a
     * regression that waits on the other side fails rather than hangs.
     *
     * @param  string  $name
     * @return void
     */
    private static function waitBriefly(string $name): void
    {
        $connection = DB::connection($name);

        $connection->statement($connection->getDriverName() === 'pgsql'
            ? sprintf('set lock_timeout = \'%ds\'', self::LOCK_TIMEOUT)
            : sprintf('set session innodb_lock_wait_timeout = %d', self::LOCK_TIMEOUT));
    }

    /**
     * Fork a worker that signs another subject in through the connection for
     * the first time, provisioning its person on the racer's connection, and
     * return once it has ended or waits on a lock.
     *
     * @param  string  $level
     * @return void
     */
    private function raceAnotherFirstSignIn(string $level): void
    {
        $sockets = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);

        self::assertIsArray($sockets);

        [$parent, $worker] = $sockets;

        $pid = pcntl_fork();

        if ($pid === 0) {
            fclose($parent);
            $this->provisionInWorker(static function (string $line) use ($worker): void {
                fwrite($worker, $line . "\n");
            }, $level);
        }

        fclose($worker);

        self::assertGreaterThan(0, $pid, 'The worker could not be forked.');

        $this->worker  = $pid;
        $this->channel = $parent;

        $this->awaitTheWorker($this->receive());
    }

    /**
     * Sign the other subject in, in the forked worker, on the racer's
     * connection, made the default and so the storage connection, at the level
     * given: report the connection's id before it starts and the outcome after,
     * then end the worker, so nothing the test set up is torn down twice.
     *
     * @param  \Closure(string): void  $send
     * @param  string  $level
     * @return never
     */
    private function provisionInWorker(\Closure $send, string $level): never
    {
        try {
            DB::setDefaultConnection(self::RACER);

            self::useIsolationLevel($level, self::RACER);
            self::waitBriefly(self::RACER);

            $racer   = DB::connection(self::RACER);
            $backend = $racer->scalar($racer->getDriverName() === 'pgsql' ? 'select pg_backend_pid()' : 'select connection_id()');

            $send(is_scalar($backend) ? (string) $backend : '');

            $this->handoff(tailor: static fn (FakeIdToken $token): FakeIdToken => $token->with('sub', self::OTHER_SUBJECT));

            $outcome = self::PROVISIONED;
        } catch (\Throwable $exception) {
            $outcome = sprintf('%s: %s', $exception::class, str_replace("\n", ' ', $exception->getMessage()));
        }

        $send($outcome);

        posix_kill((int) getmypid(), SIGKILL);

        exit(1);
    }

    /**
     * Wait until the worker has reported its outcome, or the database reports
     * its connection waiting for a lock, failing when neither comes.
     *
     * @param  string  $backend
     * @return void
     */
    private function awaitTheWorker(string $backend): void
    {
        $observer = DB::connection(self::OBSERVER);
        $query    = $observer->getDriverName() === 'pgsql'
            ? 'select count(*) from pg_stat_activity where pid = ? and wait_event_type = \'Lock\''
            : 'select count(*) from information_schema.innodb_trx where trx_mysql_thread_id = ? and trx_state = \'LOCK WAIT\'';

        for ($poll = 0; $poll < self::POLLS; $poll++) {

            $read   = [$this->channel];
            $write  = null;
            $except = null;

            if (stream_select($read, $write, $except, 0) > 0) {
                return;
            }

            $waiting = $observer->scalar($query, [(int) $backend], false);

            if (is_numeric($waiting) && (int) $waiting > 0) {
                return;
            }

            usleep(self::POLL_INTERVAL);
        }

        self::fail(sprintf('The worker on [%s] neither ended nor waited on a lock.', $backend));
    }

    /**
     * The outcome the worker reported, once it has ended.
     *
     * @return string
     */
    private function workerOutcome(): string
    {
        $outcome = $this->receive();

        $this->reap();

        return $outcome;
    }

    /**
     * The next line the worker sent.
     *
     * @return string
     */
    private function receive(): string
    {
        $channel = $this->channel;

        self::assertIsResource($channel, 'No worker was forked.');

        stream_set_timeout($channel, self::WORKER_TIMEOUT);

        $line = fgets($channel);

        self::assertIsString($line, 'The worker sent nothing.');

        return trim($line);
    }

    /**
     * End the worker, if one was forked, which has reported its outcome by now
     * or is left by a failure, wait for it, and close the line to it.
     *
     * @return void
     */
    private function reap(): void
    {
        if ($this->worker !== null) {
            posix_kill($this->worker, SIGKILL);
            pcntl_waitpid($this->worker, $status);
        }

        if (is_resource($this->channel)) {
            fclose($this->channel);
        }

        $this->worker  = null;
        $this->channel = null;
    }
}
