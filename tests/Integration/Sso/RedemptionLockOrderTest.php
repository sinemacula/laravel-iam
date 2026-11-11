<?php

declare(strict_types = 1);

namespace Tests\Integration\Sso;

use Illuminate\Contracts\Database\ConcurrencyErrorDetector;
use Illuminate\Database\DeadlockException;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Sessions\AccessTokenResult;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Iam\Exceptions\UnlinkedSignInException;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Sso\LinkRedemption;
use SineMacula\Laravel\Iam\Sso\ReauthenticationRedemption;
use SineMacula\Laravel\Iam\Sso\SignInRedemption;
use SineMacula\Laravel\Sso\Connections\ConnectionLifecycle;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Http\ClientContext as SsoClientContext;
use SineMacula\Laravel\Sso\Linking\IdentityLock;
use SineMacula\Laravel\Sso\Links\LinkService;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken;
use Tests\Concerns\MigratesSso;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Sso\Handoff;
use Tests\TestCase;

/**
 * Integration tests for the order the redemptions take their locks in, and for
 * redemptions racing the changes SSO revokes sessions for, on MySQL and
 * PostgreSQL at READ COMMITTED and REPEATABLE READ (IAM-4.1, IAM-4.2, IAM-11.1,
 * IAM-11.2).
 *
 * Every lock a redemption takes follows SSO's order: SSO's own (for a `link`,
 * the identity's guard first; the connection, the handoff code, the link), then
 * `laravel-authentication`'s connection guard, then the session's row, always
 * last. A change committed while a redemption runs, after it read but before it
 * locked (a connection disabled, a link removed, the same session renewed), is
 * either seen through the redemption's locks, or, on PostgreSQL at REPEATABLE
 * READ, fails it to serialise, and the retry helper runs the whole redemption
 * again, which sees it: a sign-in never signs anyone in through a connection or
 * link that is gone, and a renewal renews from what the other committed. A
 * `link` racing another holder of the identity's guard waits for it, and on
 * PostgreSQL at REPEATABLE READ fails to serialise and is redeemed again,
 * standalone, from its start.
 *
 * The other change is made on a second connection to the test's database, for
 * another client, so it never waits on the redemption's rows. Each race stages
 * that one interleaving, the other change committed between the redemption's
 * first plain read of its code and its first lock, which is the one a single
 * process can stage without waiting on itself; it is not a general test of
 * concurrency.
 *
 * The lock order is read from the statements on the storage connection alone:
 * the first lock of each table, in order, and every later locking statement,
 * none of which may go back to a table earlier in the order except on a row it
 * names by its id that is already locked.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SignInRedemption::class)]
#[CoversClass(ReauthenticationRedemption::class)]
#[CoversClass(LinkRedemption::class)]
final class RedemptionLockOrderTest extends TestCase
{
    use MigratesSso, RunsAtIsolationLevels, RunsSsoFlows, SignsInPeople;

    /** @var string The second connection the other change is made on. */
    private const string ELSEWHERE = 'elsewhere';

    /** @var string The IP address the other change comes from, counted apart from the tests' client. */
    private const string OTHER_IP = '192.0.2.99';

    /** @var string The connection a forked worker redeems on. */
    private const string RACER = 'racer';

    /** @var string The connection the worker's lock wait is watched from. */
    private const string OBSERVER = 'observer';

    /** @var int How long the worker's lock wait is watched for between polls, in microseconds. */
    private const int POLL_INTERVAL = 100000;

    /** @var int How many times the worker's lock wait is polled for before the test fails. */
    private const int POLLS = 100;

    /** @var int How long either side waits for a line from the other, in seconds. */
    private const int WORKER_TIMEOUT = 30;

    /** @var string The subject a second person is linked to, apart from the first's. */
    private const string OTHER_SUBJECT = 'other-subject';

    /** @var array<string, int> The rank in SSO's lock order of each table a lock is taken on. */
    private const array RANKS = [
        'sso_identity_guards'              => 1,
        'sso_enforcement'                  => 2,
        'sso_connections'                  => 3,
        'sso_domains'                      => 4,
        'sso_handoff_codes'                => 5,
        'sso_links'                        => 6,
        'authentication_connection_guards' => 8,
        'authentication_sessions'          => 9,
    ];

    /** @var \Tests\Fixtures\Models\Person The person linked to the provider's subject. */
    private Person $person;

    /** @var ?string The id of the person's link. */
    private ?string $linkId = null;

    /** @var \ArrayObject<int, array{0: string, 1: list<string>}> The statements run on the storage connection inside a transaction since recording began, each with its bindings as strings (a value that is none, empty). */
    private \ArrayObject $statements;

    /**
     * Arrange SSO, and link the person.
     *
     * @return void
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        self::requireIsolationLevels();

        $this->arrangeSso();

        $this->person     = $this->createPerson();
        $this->linkId     = $this->linkThroughFlow($this->person)->linkId;
        $this->statements = new \ArrayObject;
    }

    /**
     * A sign-in takes SSO's locks, the connection, the code and the link, then
     * `laravel-authentication`'s connection guard, then writes the session,
     * never going back to an earlier lock.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testASignInTakesSsosLocksThenTheConnectionGuardThenTheSession(string $level): void
    {
        self::useIsolationLevel($level);

        $handoff = $this->handoff();

        $this->recordStatements();

        self::assertInstanceOf(SignInResult::class, $this->redeemSignIn($handoff));

        $ranks = $this->lockRanks();

        self::assertSame([3, 5, 6, 8, 9], $ranks);
        $this->assertNoLockGoesBack();
    }

    /**
     * A re-authentication takes SSO's locks, then the session's row, last, and
     * `laravel-authentication`'s one write renews it under that lock, never
     * going back to an earlier lock.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testAReauthenticationLocksTheSessionLast(string $level): void
    {
        self::useIsolationLevel($level);

        $session = $this->signedIn();

        $this->travel(5)->seconds();

        $handoff = $this->handoff(Purpose::REAUTHENTICATE, $this->person, self::keyOf($session));

        $this->recordStatements();

        self::assertInstanceOf(AccessTokenResult::class, $this->redeemReauthentication($handoff));

        $ranks = $this->lockRanks();

        self::assertSame(9, end($ranks));
        self::assertContains(3, $ranks);
        self::assertContains(5, $ranks);
        self::assertSame($ranks, self::sorted($ranks));
        $this->assertNoLockGoesBack();
    }

    /**
     * A `link` takes the identity's guard before every other lock, then SSO's
     * own in their order, never going back to an earlier lock.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testALinkTakesTheIdentitysGuardFirst(string $level): void
    {
        self::useIsolationLevel($level);

        $person  = $this->createPerson();
        $handoff = $this->handoff(Purpose::LINK, $person, tailor: self::otherSubject(...));

        $this->recordStatements();

        self::assertTrue($this->redeemLink($handoff, $person)->isRedeemed());

        $ranks = $this->lockRanks();

        self::assertSame(1, $ranks[0] ?? null);
        self::assertContains(3, $ranks);
        self::assertContains(5, $ranks);
        self::assertSame($ranks, self::sorted($ranks));
        $this->assertNoLockGoesBack();
    }

    /**
     * A `link` redeemed while another transaction holds the identity's guard
     * waits for it and links the person in one call: on PostgreSQL at
     * REPEATABLE READ it fails to serialise once the other commits, and SSO
     * runs its standalone transaction again.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testALinkRacingAHolderOfTheIdentitysGuardLinks(string $level): void
    {
        self::requireAFork();
        self::useIsolationLevel($level);

        $person    = $this->createPerson();
        $handoff   = $this->handoff(Purpose::LINK, $person, tailor: self::otherSubject(...));
        $reference = self::referenceOf($person);
        $digest    = IdentityLock::digest($reference);

        DB::transaction(fn () => $this->app?->make(IdentityLock::class)->acquire($reference));

        $outcome = $this->raceForTheGuard(
            static fn (): int => DB::table('sso_identity_guards')->where('identity_hash', $digest)->update(['identity_hash' => $digest]),
            fn (): string => $this->redeemLink($handoff, $person)->status->value,
            $level,
        );

        self::assertSame('redeemed', $outcome);
        self::assertCount(1, $this->app?->make(LinkService::class)->list($reference) ?? []);
    }

    /**
     * A connection disabled while a sign-in through it runs, after the sign-in
     * read and before it locked, is seen: the sign-in is refused, no session is
     * written, and on PostgreSQL at REPEATABLE READ it is first run again from
     * its start, once.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testASignInRacingAConnectionDisableNeverSignsIn(string $level): void
    {
        self::useIsolationLevel($level);

        $handoff = $this->handoff();
        $runs    = $this->whenTheCodeIsRead(function (): void {

            self::assertTrue($this->app?->make(ConnectionLifecycle::class)->disable(self::TENANT, $this->connectionId, new SsoClientContext(self::OTHER_IP, null))->isSucceeded());
        });

        $answer = $this->redeemSignIn($handoff);

        self::assertInstanceOf(RedemptionResult::class, $answer);
        self::assertTrue($answer->isRefused());
        self::assertSame(0, DB::table('authentication_sessions')->count());
        self::assertCount(self::isSnapshotRetried($level) ? 2 : 1, $runs);
    }

    /**
     * A link removed while a sign-in through it runs, after the sign-in read
     * and before it locked, is seen: nobody is signed in, and on PostgreSQL at
     * REPEATABLE READ the sign-in is first run again from its start, once.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testASignInRacingALinkRemovalNeverSignsIn(string $level): void
    {
        self::useIsolationLevel($level);

        $handoff = $this->handoff();
        $runs    = $this->whenTheCodeIsRead(function (): void {

            $removed = $this->app?->make(LinkService::class)->remove(self::referenceOf($this->person), (string) $this->linkId, new SsoClientContext(self::OTHER_IP, null));

            self::assertTrue($removed?->isRemoved());
        });

        try {
            $answer = $this->redeemSignIn($handoff);

            self::assertInstanceOf(RedemptionResult::class, $answer);
            self::assertTrue($answer->isRefused());
        } catch (UnlinkedSignInException) {
            // SSO admitted the result unlinked; the redemption rolled back.
        }

        self::assertSame(0, DB::table('authentication_sessions')->count());
        self::assertCount(self::isSnapshotRetried($level) ? 2 : 1, $runs);
    }

    /**
     * Two re-authentications racing for one session both renew it: the later,
     * after the other committed, waits for nothing it holds, and on PostgreSQL
     * at REPEATABLE READ fails to serialise at the session's row and is run
     * again from its start, once, renewing from what the other committed.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testTwoReauthenticationsRacingForOneSessionBothRenew(string $level): void
    {
        self::useIsolationLevel($level);

        $session = $this->signedIn();

        $this->travel(5)->seconds();

        $first  = $this->handoff(Purpose::REAUTHENTICATE, $this->person, self::keyOf($session));
        $second = $this->handoff(Purpose::REAUTHENTICATE, $this->person, self::keyOf($session));

        /** @var \ArrayObject<int, \SineMacula\Laravel\Authentication\Sessions\AccessTokenResult|\SineMacula\Laravel\Sso\Handoffs\RedemptionResult> $other */
        $other = new \ArrayObject;
        $runs  = $this->whenTheCodeIsRead(function () use ($second, $other): void {

            $other->append(Iam::reauthentications()->redeem(self::GUARD, $this->connectionId, $second->code, $second->verifier, new ClientContext(self::OTHER_IP, null)));
        });

        $answer = $this->redeemReauthentication($first);

        self::assertInstanceOf(AccessTokenResult::class, $answer);
        self::assertTrue($answer->isIssued());
        self::assertInstanceOf(AccessTokenResult::class, $other[0]);
        self::assertTrue($other[0]->isIssued());
        self::assertCount(self::isSnapshotRetried($level) ? 2 : 1, $runs);
    }

    /**
     * A sign-in racing a connection disable whose last attempt fails to
     * serialise, on PostgreSQL at REPEATABLE READ with one attempt configured,
     * throws a failure Laravel's detector recognises, so the caller retries the
     * request; no session is written. At every other level it waits, and is
     * refused.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testASignInWhoseLastAttemptFailsToSerialiseThrowsAConcurrencyFailure(string $level): void
    {
        self::useIsolationLevel($level);

        Config::set('iam.transactions.attempts', 1);

        $handoff = $this->handoff();
        $runs    = $this->whenTheCodeIsRead(function (): void {

            self::assertTrue($this->app?->make(ConnectionLifecycle::class)->disable(self::TENANT, $this->connectionId, new SsoClientContext(self::OTHER_IP, null))->isSucceeded());
        });

        try {
            $answer = $this->redeemSignIn($handoff);
        } catch (\Throwable $exception) {
            $answer = $exception;
        }

        if (self::isSnapshotRetried($level)) {
            $this->assertRaisedBySerialisation($answer);
        } else {
            self::assertInstanceOf(RedemptionResult::class, $answer);
            self::assertTrue($answer->isRefused());
        }

        self::assertSame(0, DB::table('authentication_sessions')->count());
        self::assertCount(1, $runs);
    }

    /**
     * A re-authentication racing another for the same session whose last
     * attempt fails to serialise, on PostgreSQL at REPEATABLE READ with one
     * attempt configured, throws a failure Laravel's detector recognises, and
     * leaves its code unspent, so the request retried renews the session. At
     * every other level it waits, and renews.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testAReauthenticationWhoseLastAttemptFailsToSerialiseThrowsAConcurrencyFailure(string $level): void
    {
        self::useIsolationLevel($level);

        $session = $this->signedIn();

        Config::set('iam.transactions.attempts', 1);

        $this->travel(5)->seconds();

        $first  = $this->handoff(Purpose::REAUTHENTICATE, $this->person, self::keyOf($session));
        $second = $this->handoff(Purpose::REAUTHENTICATE, $this->person, self::keyOf($session));

        /** @var \ArrayObject<int, \SineMacula\Laravel\Authentication\Sessions\AccessTokenResult|\SineMacula\Laravel\Sso\Handoffs\RedemptionResult> $other */
        $other = new \ArrayObject;
        $runs  = $this->whenTheCodeIsRead(function () use ($second, $other): void {

            $other->append(Iam::reauthentications()->redeem(self::GUARD, $this->connectionId, $second->code, $second->verifier, new ClientContext(self::OTHER_IP, null)));
        });

        try {
            $answer = $this->redeemReauthentication($first);
        } catch (\Throwable $exception) {
            $answer = $exception;
        }

        self::assertInstanceOf(AccessTokenResult::class, $other[0]);
        self::assertTrue($other[0]->isIssued());
        self::assertCount(1, $runs);

        if (self::isSnapshotRetried($level)) {
            $this->assertRaisedBySerialisation($answer);

            $answer = $this->redeemReauthentication($first);
        }

        self::assertInstanceOf(AccessTokenResult::class, $answer);
        self::assertTrue($answer->isIssued());
    }

    /**
     * Assert that what the redemption answered is a failure to serialise that
     * Laravel's concurrency detector recognises, the database's own behind it.
     *
     * @param  mixed  $answer
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function assertRaisedBySerialisation(mixed $answer): void
    {
        self::assertInstanceOf(DeadlockException::class, $answer);
        self::assertTrue($this->app?->make(ConcurrencyErrorDetector::class)->causedByConcurrencyError($answer));

        $raised = $answer;

        while ($raised instanceof DeadlockException) {
            $raised = $raised->getPrevious();
        }

        self::assertInstanceOf(QueryException::class, $raised);
        self::assertSame('40001', $raised->getCode());
    }

    /**
     * Sign the person in through SSO, and answer the session.
     *
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession
     *
     * @throws \Throwable
     */
    private function signedIn(): EloquentSession&Model
    {
        $signIn = $this->redeemSignIn($this->handoff());

        self::assertInstanceOf(SignInResult::class, $signIn);

        return $signIn->session->record ?? self::fail('The person was not signed in.');
    }

    /**
     * Redeem the `sign_in` handoff for the tests' client.
     *
     * @param  \Tests\Fixtures\Sso\Handoff  $handoff
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult|\SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     *
     * @throws \Throwable
     */
    private function redeemSignIn(Handoff $handoff): RedemptionResult|SignInResult
    {
        return Iam::signIns()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, new SignInContext(self::client()));
    }

    /**
     * Redeem the `reauthenticate` handoff for the tests' client.
     *
     * @param  \Tests\Fixtures\Sso\Handoff  $handoff
     * @return \SineMacula\Laravel\Authentication\Sessions\AccessTokenResult|\SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     *
     * @throws \Throwable
     */
    private function redeemReauthentication(Handoff $handoff): AccessTokenResult|RedemptionResult
    {
        return Iam::reauthentications()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, self::client());
    }

    /**
     * Redeem the `link` handoff for the tests' client, as the person.
     *
     * @param  \Tests\Fixtures\Sso\Handoff  $handoff
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     *
     * @throws \Throwable
     */
    private function redeemLink(Handoff $handoff, Person $person): RedemptionResult
    {
        return Iam::links()->redeem($this->connectionId, $handoff->code, $handoff->verifier, self::client(), $this->requestCallerOf($person));
    }

    /**
     * The ID token, naming a subject no one is linked to yet.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken  $token
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken
     */
    private static function otherSubject(FakeIdToken $token): FakeIdToken
    {
        return $token->with('sub', self::OTHER_SUBJECT);
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
     * Hold what the first side locks in a transaction left open on the storage
     * connection, run the second side in a forked worker, commit once the
     * database reports the worker waiting on a lock, and return what the worker
     * reported once it went on.
     *
     * @param  \Closure(): mixed  $hold
     * @param  \Closure(): string  $second
     * @param  string  $level
     * @return string
     *
     * @throws \Throwable
     */
    private function raceForTheGuard(\Closure $hold, \Closure $second, string $level): string
    {
        Config::set('database.connections.' . self::RACER, Config::get('database.connections.' . self::CONNECTION));
        Config::set('database.connections.' . self::OBSERVER, Config::get('database.connections.' . self::CONNECTION));

        $sockets = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);

        self::assertIsArray($sockets);

        [$parent, $worker] = $sockets;

        $send = static function (string $line) use ($worker): void {
            fwrite($worker, $line . "\n");
        };

        $receive = static function () use ($parent): string {

            stream_set_timeout($parent, self::WORKER_TIMEOUT);

            $line = fgets($parent);

            self::assertIsString($line, 'The worker sent nothing.');

            return trim($line);
        };

        $connection = DB::connection(self::CONNECTION);

        $connection->beginTransaction();

        $hold();

        $pid = pcntl_fork();

        if ($pid === 0) {
            fclose($parent);
            self::runInWorker($second, $send, $level);
        }

        fclose($worker);

        try {
            self::assertGreaterThan(0, $pid, 'The worker could not be forked.');

            self::awaitLockWait($receive());

            $connection->commit();

            return $receive();
        } finally {
            if ($connection->transactionLevel() > 0) {
                $connection->rollBack();
            }

            if ($pid > 0) {
                pcntl_waitpid($pid, $status);
            }
        }
    }

    /**
     * Run the second side in the forked worker, on the racer's connection, as
     * the default and so the storage connection, at the level given: report the
     * connection's id before it starts and the outcome after, then end the
     * worker, so nothing the test set up is torn down twice.
     *
     * @param  \Closure(): string  $second
     * @param  \Closure(string): void  $send
     * @param  string  $level
     * @return never
     */
    private static function runInWorker(\Closure $second, \Closure $send, string $level): never
    {
        try {
            DB::setDefaultConnection(self::RACER);

            self::useIsolationLevel($level, self::RACER);

            $racer   = DB::connection(self::RACER);
            $backend = $racer->scalar($racer->getDriverName() === 'pgsql' ? 'select pg_backend_pid()' : 'select connection_id()');

            $send(is_scalar($backend) ? (string) $backend : '');

            $outcome = $second();
        } catch (\Throwable $exception) {
            $outcome = sprintf('%s: %s', $exception::class, str_replace("\n", ' ', $exception->getMessage()));
        }

        $send($outcome);

        posix_kill((int) getmypid(), SIGKILL);

        exit(1);
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
     * Run the change on the second connection, made the default (and so the
     * storage connection) while it runs, once the redemption first reads its
     * code on the storage connection inside its transaction, after it has read
     * and before it locks; and answer each time the redemption read its code
     * there, one for every time it ran.
     *
     * @param  \Closure(): void  $change
     * @return \ArrayObject<int, true>
     */
    private function whenTheCodeIsRead(\Closure $change): \ArrayObject
    {
        Config::set('database.connections.' . self::ELSEWHERE, Config::get('database.connections.' . self::CONNECTION));

        $elsewhere = DB::connection(self::ELSEWHERE);

        // Never wait long on a lock the redemption holds.
        $elsewhere->statement($elsewhere->getDriverName() === 'pgsql' ? 'set lock_timeout = \'5s\'' : 'set session innodb_lock_wait_timeout = 5');

        /** @var \ArrayObject<int, true> $runs */
        $runs  = new \ArrayObject;
        $owner = DB::connection(self::CONNECTION);

        $owner->listen(static function (QueryExecuted $query) use ($runs, $change): void {

            if ($query->connectionName !== self::CONNECTION || $query->connection->transactionLevel() === 0 || !self::readsTheCode($query->sql)) {
                return;
            }

            $runs->append(true);

            if ($runs->count() > 1) {
                return;
            }

            $default = DB::getDefaultConnection();

            DB::setDefaultConnection(self::ELSEWHERE);

            try {
                $change();
            } finally {
                DB::setDefaultConnection($default);
            }
        });

        return $runs;
    }

    /**
     * Whether the statement is the redemption's plain read of its code.
     *
     * @param  string  $sql
     * @return bool
     */
    private static function readsTheCode(string $sql): bool
    {
        $sql = strtolower($sql);

        return str_starts_with($sql, 'select') && self::tableOf($sql) === 'sso_handoff_codes' && !str_contains($sql, 'for update');
    }

    /**
     * Whether the isolation level and driver retry a redemption that locks a
     * row another committed after it read: PostgreSQL's REPEATABLE READ.
     *
     * @param  string  $level
     * @return bool
     */
    private static function isSnapshotRetried(string $level): bool
    {
        return DB::connection()->getDriverName() === 'pgsql' && $level === 'repeatable read';
    }

    /**
     * Start recording the statements run on the storage connection, and on it
     * alone, inside a transaction, each with its bindings as strings, in the
     * order they are bound.
     *
     * @return void
     */
    private function recordStatements(): void
    {
        $statements = $this->statements;

        DB::connection(self::CONNECTION)->listen(static function (QueryExecuted $query) use ($statements): void {

            if ($query->connectionName !== self::CONNECTION || $query->connection->transactionLevel() <= 0) {
                return;
            }

            $bindings = array_values(array_map(
                static fn (mixed $binding): string => match (true) {
                    is_bool($binding)   => (string) (int) $binding,
                    is_scalar($binding) => (string) $binding,
                    default             => '',
                },
                $query->bindings,
            ));

            $statements->append([strtolower($query->sql), $bindings]);
        });
    }

    /**
     * The rank in SSO's lock order of each table first locked since recording
     * began, in the order first locked: by a locking read or by a write of a
     * table the order names. A later write of a table already locked is not
     * counted again here; `assertNoLockGoesBack()` checks every one of them.
     *
     * @return list<int>
     */
    private function lockRanks(): array
    {
        $ranks = [];

        foreach ($this->statements as [$sql]) {

            $rank = self::rankOf($sql);

            if ($rank === null || in_array($rank, $ranks, true)) {
                continue;
            }

            $ranks[] = $rank;
        }

        return $ranks;
    }

    /**
     * Assert that every locking statement since recording began, not only the
     * first of each table, follows the order: one on a table earlier in the
     * order than a lock already taken is allowed only as a write or a locking
     * read of a row it names by its id that an earlier locking statement on
     * that table already locked, which takes no new lock.
     *
     * @return void
     */
    private function assertNoLockGoesBack(): void
    {
        $highest = 0;
        $locked  = [];

        foreach ($this->statements as [$sql, $bindings]) {

            $rank = self::rankOf($sql);

            if ($rank === null) {
                continue;
            }

            $table = (string) self::tableOf($sql);

            if ($rank < $highest) {

                $id = self::idBoundIn($sql, $bindings);

                self::assertTrue($id !== null && in_array($id, $locked[$table] ?? [], true), 'A lock goes back in the order: ' . $sql);
            }

            $highest        = max($highest, $rank);
            $locked[$table] = [...$locked[$table] ?? [], ...$bindings];
        }
    }

    /**
     * The rank in SSO's lock order of the table the statement locks, or `null`
     * when it locks none the order names: a plain read locks nothing.
     *
     * @param  string  $sql
     * @return ?int
     */
    private static function rankOf(string $sql): ?int
    {
        if (str_starts_with($sql, 'select') && !str_contains($sql, 'for update') && !str_contains($sql, 'for share')) {
            return null;
        }

        return self::RANKS[(string) self::tableOf($sql)] ?? null;
    }

    /**
     * The id the statement names its row by (`where id = ?`, qualified or not),
     * as bound, or `null` when it names none.
     *
     * @param  string  $sql
     * @param  list<string>  $bindings
     * @return ?string
     */
    private static function idBoundIn(string $sql, array $bindings): ?string
    {
        if (preg_match('/\bwhere\s+(?:["`]?[a-z0-9_]+["`]?\.)?["`]?id["`]?\s*=\s*\?/', $sql, $matches, PREG_OFFSET_CAPTURE) !== 1) {
            return null;
        }

        $end = $matches[0][1] + strlen($matches[0][0]);

        return $bindings[substr_count(substr($sql, 0, $end), '?') - 1] ?? null;
    }

    /**
     * The ranks, ascending.
     *
     * @param  list<int>  $ranks
     * @return list<int>
     */
    private static function sorted(array $ranks): array
    {
        sort($ranks);

        return $ranks;
    }

    /**
     * The table the statement reads or writes first, unquoted.
     *
     * @param  string  $sql
     * @return ?string
     */
    private static function tableOf(string $sql): ?string
    {
        return preg_match('/\b(?:from|into|update)\s+["`]?([a-z0-9_]+)["`]?/', $sql, $matches) === 1 ? $matches[1] : null;
    }
}
