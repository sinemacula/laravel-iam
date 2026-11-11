<?php

declare(strict_types = 1);

namespace Tests\Integration\Authorization;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Sso\IdentityGuards;
use SineMacula\Laravel\Iam\Tenancy\TreeChanges;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Linking\IdentityLock;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken;
use Tests\Concerns\MigratesAuthorization;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Authorization\Organisation;
use Tests\Fixtures\Authorization\OrganisationTenancy;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Tenancy\StoredTenantTree;
use Tests\TestCase;

/**
 * Integration tests for the order a move of the application's tree takes SSO's
 * locks in while it reports the people granted in the moved subtree to SSO's
 * scope widening (IAM-6.7, IAM-7.5, IAM-11.1): two people granted in the moved
 * tenant, each linked by a verified domain through the same connection of the
 * tenant above it.
 *
 * SSO's lock order is the identity guard, then the connections, then the links,
 * and several guards in ascending order of SSO's digest. The move takes every
 * grantee's guard, in that order, before any statement touches a connection, on
 * every engine. A grant to the second grantee, made on another connection once
 * the move has locked the shared connection, waits for the move and goes on:
 * the move commits, and neither is aborted for a deadlock, which taking the
 * second guard after the connection would have caused. The race runs on MySQL
 * and PostgreSQL at READ COMMITTED and REPEATABLE READ, the grant in a forked
 * worker, the move outside any retry, so a deadlock fails it rather than being
 * run again; on PostgreSQL at REPEATABLE READ the grant may first fail to
 * serialise once the move commits, and is made again.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TreeChanges::class)]
#[CoversClass(IdentityGuards::class)]
#[WithConfig('authorization.tenant_tree', StoredTenantTree::class, defer: false)]
final class TreeMoveLockOrderTest extends TestCase
{
    use MigratesAuthorization, RunsAtIsolationLevels, RunsSsoFlows, SignsInPeople;

    /** @var string The tenant of both links by a verified domain. */
    private const string LINKED = 'linked';

    /** @var string The tenant below the linked one both people are granted in, and that moves. */
    private const string GRANTED = 'granted';

    /** @var string The tenant the racing grant is made in. */
    private const string ELSEWHERE_TENANT = 'elsewhere';

    /** @var string The role granted. */
    private const string ROLE = 'editor';

    /** @var string The subject the second person is linked to, apart from the first's. */
    private const string SECOND_SUBJECT = 'second-subject';

    /** @var string What MySQL and PostgreSQL say when they abort a transaction for a deadlock. */
    private const string DEADLOCK = '/Deadlock found|deadlock detected/i';

    /** @var string The connection the forked worker grants on. */
    private const string RACER = 'racer';

    /** @var string The connection the worker's lock wait is watched from. */
    private const string OBSERVER = 'observer';

    /** @var int How long the worker's lock wait is watched for between polls, in microseconds. */
    private const int POLL_INTERVAL = 100000;

    /** @var int How many times the worker's lock wait is polled for before the test fails. */
    private const int POLLS = 100;

    /** @var int How long the parent waits for a line from the worker, in seconds. */
    private const int WORKER_TIMEOUT = 30;

    /** @var array<string, \Tests\Fixtures\Models\Person> The two people granted in the moved tenant, by SSO's digest of each. */
    private array $people = [];

    /** @var list<string> The ids of their links by a verified domain. */
    private array $links = [];

    /**
     * Arrange SSO, the tree (the granted tenant below the linked one, and a
     * tenant apart), the role, and two people granted it in the granted tenant,
     * each then linked by a verified domain through the linked tenant's
     * connection.
     *
     * @return void
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeSso();

        StoredTenantTree::place(self::organisation(self::LINKED));
        StoredTenantTree::place(self::organisation(self::GRANTED), self::organisation(self::LINKED));
        StoredTenantTree::place(self::organisation(self::ELSEWHERE_TENANT));

        $this->app?->instance(TenantResolver::class, new OrganisationTenancy);

        Role::query()->create(['name' => self::ROLE]);

        $this->connectionId = $this->makeConnection(self::LINKED);

        foreach ([null, self::SECOND_SUBJECT] as $subject) {

            $person = $this->createPerson();

            $this->grant($person, self::GRANTED);

            $this->links[] = $this->link($person, $subject);

            $this->people[IdentityLock::digest(self::referenceOf($person))] = $person;
        }

        Link::query()->whereKey($this->links)->update(['provenance' => LinkOrigin::VERIFIED_DOMAIN->value]);
    }

    /**
     * A move takes the guard of every person granted in the moved subtree, in
     * ascending order of SSO's digest, before any statement touches a
     * connection, and suspends both links.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testEveryGranteesGuardIsTakenBeforeAnyConnectionIsTouched(?string $level): void
    {
        self::runAtIsolationLevel($level);

        /** @var \ArrayObject<int, string> $statements */
        $statements = new \ArrayObject;

        DB::listen(function (QueryExecuted $query) use ($statements): void {

            if ($query->connection->transactionLevel() === 0) {
                return;
            }

            $statement = $this->lockStatement($query);

            if ($statement === null) {
                return;
            }

            $statements->append($statement);
        });

        Iam::transaction(function (): void {

            StoredTenantTree::place(self::organisation(self::GRANTED));

            Iam::treeChanges()->changed(self::GRANTED);
        });

        $digests = array_keys($this->people);

        sort($digests, SORT_STRING);

        $recorded   = $statements->getArrayCopy();
        $connection = array_search('connection', $recorded, true);

        self::assertIsInt($connection, 'No statement touched a connection.');
        self::assertSame($digests, array_values(array_unique(array_slice($recorded, 0, $connection))));

        foreach ($this->links as $link) {
            self::assertSame(LinkState::SUSPENDED, Link::query()->findOrFail($link)->state);
        }
    }

    /**
     * A grant to the second person granted in the moved subtree, made on
     * another connection once the move has locked the connection both links are
     * in, waits for the move and is made: the move commits, and neither is
     * aborted for a deadlock.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testAMoveRacingAGrantToASecondGranteeNeverDeadlocks(string $level): void
    {
        self::requireIsolationLevels();
        self::requireAFork();
        self::useIsolationLevel($level);

        Config::set('database.connections.' . self::RACER, Config::get('database.connections.' . self::CONNECTION));
        Config::set('database.connections.' . self::OBSERVER, Config::get('database.connections.' . self::CONNECTION));

        /** @var \ArrayObject<string, mixed> $race */
        $race = new \ArrayObject(['first' => null, 'pid' => 0, 'receive' => null]);

        DB::listen(function (QueryExecuted $query) use ($race, $level): void {

            if ($query->connectionName !== self::CONNECTION || $race['pid'] !== 0 || $query->connection->transactionLevel() === 0) {
                return;
            }

            $statement = $this->lockStatement($query);

            if ($statement === null) {
                return;
            }

            if ($statement !== 'connection') {
                $race['first'] ??= $statement;

                return;
            }

            $this->raceAGrant($race, $level);
        });

        try {
            $moved = $this->moveOutsideAnyRetry();
        } finally {
            $outcome = $this->workerOutcome($race);
        }

        self::assertSame('moved', $moved);
        self::assertDoesNotMatchRegularExpression(self::DEADLOCK, $outcome);
        self::assertStringEndsWith('granted', $outcome);
    }

    /**
     * Grant the role to the person in the tenant alone.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  string  $tenantId
     * @return void
     *
     * @throws \Throwable
     */
    private function grant(Person $person, string $tenantId): void
    {
        $service = $this->app?->make(GrantService::class) ?? self::fail('The application has not booted.');

        $service->grantRole($person, self::ROLE, tenant: new Reference(Organisation::TYPE, $tenantId), includeSubtree: false);
    }

    /**
     * Link the person through the tests' connection to the provider's subject,
     * or to the subject given, and answer the link's id.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  ?string  $subject
     * @return string
     *
     * @throws \Random\RandomException
     */
    private function link(Person $person, ?string $subject): string
    {
        $tailor  = $subject === null ? null : static fn (FakeIdToken $token): FakeIdToken => $token->with('sub', $subject);
        $handoff = $this->handoff(Purpose::LINK, $person, tailor: $tailor);
        $linked  = Iam::links()->redeem($this->connectionId, $handoff->code, $handoff->verifier, self::client(), $this->requestCallerOf($person));

        self::assertTrue($linked->isRedeemed(), sprintf('The person was not linked: [%s].', $linked->reason->value ?? $linked->status->value));

        return (string) $linked->linkId;
    }

    /**
     * What the statement locks in SSO's order: the digest of the identity whose
     * guard it takes, `connection` for one touching a connection, or `null`.
     *
     * @param  \Illuminate\Database\Events\QueryExecuted  $query
     * @return ?string
     */
    private function lockStatement(QueryExecuted $query): ?string
    {
        if (str_contains($query->sql, 'sso_connections')) {
            return 'connection';
        }

        if (!str_contains($query->sql, 'sso_identity_guards') || !str_starts_with(strtolower(ltrim($query->sql)), 'insert')) {
            return null;
        }

        foreach ($query->bindings as $binding) {
            if (is_string($binding) && array_key_exists($binding, $this->people)) {
                return $binding;
            }
        }

        return null;
    }

    /**
     * Move the granted tenant out from under the linked one and report it, in
     * one transaction run once, never again; answer `moved`, or what failed it.
     *
     * @return string
     */
    private function moveOutsideAnyRetry(): string
    {
        try {
            DB::connection(self::CONNECTION)->transaction(function (): void {

                StoredTenantTree::place(self::organisation(self::GRANTED));

                Iam::treeChanges()->changed(self::GRANTED);
            }, 1);

            return 'moved';
        } catch (\Throwable $exception) {
            return self::describe($exception);
        }
    }

    /**
     * Fork a worker that grants the role to the person whose guard the move did
     * not take first, in another tenant, on the racer's connection, and wait
     * until the database reports it waiting on a lock.
     *
     * @param  \ArrayObject<string, mixed>  $race
     * @param  string  $level
     * @return void
     */
    private function raceAGrant(\ArrayObject $race, string $level): void
    {
        $second = array_values(array_filter($this->people, static fn (string $digest): bool => $digest !== $race['first'], ARRAY_FILTER_USE_KEY))[0];
        $pair   = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);

        self::assertIsArray($pair);

        [$parent, $worker] = $pair;

        $send = static function (string $line) use ($worker): void {
            fwrite($worker, $line . "\n");
        };

        $receive = static function () use ($parent): string {

            stream_set_timeout($parent, self::WORKER_TIMEOUT);

            $line = fgets($parent);

            self::assertIsString($line, 'The worker sent nothing.');

            return trim($line);
        };

        $pid = pcntl_fork();

        if ($pid === 0) {
            fclose($parent);
            $this->grantInWorker($second, $send, $level);
        }

        fclose($worker);

        self::assertGreaterThan(0, $pid, 'The worker could not be forked.');

        $race['pid']     = $pid;
        $race['receive'] = $receive;

        self::awaitLockWait($receive());
    }

    /**
     * In the forked worker, on the racer's connection made the default, grant
     * the role to the person in a tenant apart, inside a transaction of its own
     * run once, then once more should it fail; report the connection's id
     * before it starts and how each try went after, then end the worker, so
     * nothing the test set up is torn down twice.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  \Closure(string): void  $send
     * @param  string  $level
     * @return never
     */
    private function grantInWorker(Person $person, \Closure $send, string $level): never
    {
        $tries = [];

        try {
            DB::setDefaultConnection(self::RACER);

            self::useIsolationLevel($level, self::RACER);

            $racer   = DB::connection(self::RACER);
            $backend = $racer->scalar($racer->getDriverName() === 'pgsql' ? 'select pg_backend_pid()' : 'select connection_id()');

            $send(is_scalar($backend) ? (string) $backend : '');

            for ($try = 0; $try < 2; $try++) {
                try {
                    $racer->transaction(fn () => $this->grant($person, self::ELSEWHERE_TENANT), 1);

                    $tries[] = 'granted';

                    break;
                } catch (\Throwable $exception) {
                    $tries[] = self::describe($exception);
                }
            }
        } catch (\Throwable $exception) {
            $tries[] = self::describe($exception);
        }

        $send(implode(' | ', $tries));

        posix_kill((int) getmypid(), SIGKILL);

        exit(1);
    }

    /**
     * What the worker reported once it went on, after reaping it; `none` when
     * no worker was forked.
     *
     * @param  \ArrayObject<string, mixed>  $race
     * @return string
     */
    private function workerOutcome(\ArrayObject $race): string
    {
        $pid     = $race['pid'];
        $receive = $race['receive'];

        if (!is_int($pid) || $pid <= 0 || !$receive instanceof \Closure) {
            return 'none';
        }

        try {
            $outcome = $receive();

            return is_string($outcome) ? $outcome : '';
        } finally {
            pcntl_waitpid($pid, $status);
        }
    }

    /**
     * The exception's class and message, and those of every exception that
     * caused it, on one line.
     *
     * @param  \Throwable  $exception
     * @return string
     */
    private static function describe(\Throwable $exception): string
    {
        $described = [];

        for ($cause = $exception; $cause !== null; $cause = $cause->getPrevious()) {
            $described[] = sprintf('%s: %s', $cause::class, str_replace("\n", ' ', $cause->getMessage()));
        }

        return implode(' <- ', $described);
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
     * Wait until the database reports the worker's connection waiting for a row
     * lock, failing when it never does.
     *
     * @param  string  $backend
     * @return void
     */
    private static function awaitLockWait(string $backend): void
    {
        $observer = DB::connection(self::OBSERVER);
        $query    = $observer->getDriverName() === 'pgsql'
            ? 'select count(*) from pg_stat_activity where pid = ? and wait_event_type = \'Lock\''
            : 'select count(*) from information_schema.innodb_trx where trx_mysql_thread_id = ? and trx_state = \'LOCK WAIT\'';

        for ($poll = 0; $poll < self::POLLS; $poll++) {

            $waiting = $observer->scalar($query, [(int) $backend], false);

            if (is_numeric($waiting) && (int) $waiting > 0) {
                return;
            }

            usleep(self::POLL_INTERVAL);
        }

        self::fail(sprintf('The worker never waited on a lock; it reported [%s].', $backend));
    }

    /**
     * `laravel-authorization`'s reference to the organisation of the id.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     */
    private static function organisation(string $id): Reference
    {
        return new Reference(Organisation::TYPE, $id);
    }
}
