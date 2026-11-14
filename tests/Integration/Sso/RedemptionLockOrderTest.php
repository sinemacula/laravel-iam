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
use SineMacula\Laravel\Iam\Sso\ReauthenticationRedemption;
use SineMacula\Laravel\Iam\Sso\SignInRedemption;
use SineMacula\Laravel\Sso\Connections\ConnectionLifecycle;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Http\ClientContext as SsoClientContext;
use SineMacula\Laravel\Sso\Links\LinkService;
use Tests\Concerns\MigratesSso;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Sso\Handoff;
use Tests\TestCase;

/**
 * Integration tests for the redemptions' lock order, and for redemptions racing
 * SSO's revoking changes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SignInRedemption::class)]
#[CoversClass(ReauthenticationRedemption::class)]
final class RedemptionLockOrderTest extends TestCase
{
    use MigratesSso, RunsAtIsolationLevels, RunsSsoFlows, SignsInPeople;

    /** @var string The second connection the other change is made on. */
    private const string ELSEWHERE = 'elsewhere';

    /** @var string The IP address the other change comes from, counted apart from the tests' client. */
    private const string OTHER_IP = '192.0.2.99';

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
     * A sign-in locks SSO's rows, the connection guard, then the session.
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
     * A re-authentication locks the session's row last.
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
     * A sign-in racing a connection disable never signs in.
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
     * A sign-in racing a link removal never signs in.
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
     * Two re-authentications racing for one session both renew it.
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
     * A sign-in whose last attempt fails to serialise throws.
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
     * A re-authentication whose last attempt fails to serialise throws.
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
     * Assert the answer is a serialisation failure Laravel's detector knows.
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
     * Run the change elsewhere once the redemption first reads its code.
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
     * Whether the level and driver retry a redemption on a stale snapshot.
     *
     * @param  string  $level
     * @return bool
     */
    private static function isSnapshotRetried(string $level): bool
    {
        return DB::connection()->getDriverName() === 'pgsql' && $level === 'repeatable read';
    }

    /**
     * Record the statements run on the storage connection in a transaction.
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
     * The lock-order rank of each table, in the order first locked.
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
     * Assert no locking statement goes back in the lock order.
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
     * The table's rank in SSO's lock order, or `null` when it locks none.
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
     * The id the statement names its row by, or `null` when it names none.
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
