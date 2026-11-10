<?php

declare(strict_types = 1);

namespace Tests\Integration\Sso;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Database\StorageConnection;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Sso\ReauthenticationSessionsAdapter;
use SineMacula\Laravel\Iam\Sso\RenewalRecorder;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Flows\Enums\SessionStanding;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use Tests\Concerns\FindsLockedSessions;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Concerns\SignsInThroughLinks;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * Integration tests for SSO's reauthentication sessions through
 * `laravel-authentication` (IAM-4.2): a flow's start answered from the
 * session's external standing through the connection by any link, on whichever
 * guard holds the session, locking nothing; the redemption's locked standing
 * through exactly the link, on the application's guard, locking the session's
 * row last until the redemption's transaction ends; any reason
 * `laravel-authentication` gives answered `not_signed_in`, never thrown; what
 * cannot be resolved thrown (IAM-8.2); and the renewal recorded once and never
 * written.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReauthenticationSessionsAdapter::class)]
final class ReauthenticationSessionsAdapterTest extends TestCase
{
    use FindsLockedSessions, MigratesMembers, RunsAtIsolationLevels, SignsInPeople, SignsInThroughLinks;

    /** @var string What a renewal asked for while no redemption is open to write it is. */
    private const string NO_REDEMPTION = 'SSO asked for a renewal no redemption would write: a re-authentication is redeemed through Iam::reauthentications().';

    /** @var string A second guard holding sessions, which people sign in on through the same connections. */
    private const string ADMIN = 'admin';

    /** @var string A statement that writes, or a read that locks. */
    private const string WRITES_OR_LOCKS = '/^\s*(insert|update|delete)|for update|for share|lock in share mode/i';

    /**
     * A session established through the connection, by any link, stands as a
     * flow starts.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionThroughTheConnectionStandsAsAFlowStarts(): void
    {
        $person  = $this->createPerson();
        $session = $this->signInThrough($person);

        self::assertSame(SessionStanding::SIGNED_IN, $this->adapter()->standing(self::referenceOf($person), self::keyOf($session), self::connection()));
    }

    /**
     * A session SSO names with no application stands on whichever guard holds
     * it, though the other guards answer it is not theirs.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionOfAnotherGuardStandsAsAFlowStarts(): void
    {
        $person  = $this->createPerson();
        $session = $this->signInThrough($person, guard: self::ADMIN);

        self::assertSame(self::ADMIN, $session->getGuard());
        self::assertSame(SessionStanding::SIGNED_IN, $this->adapter()->standing(self::referenceOf($person), self::keyOf($session), self::connection()));
    }

    /**
     * Rows of `[case]`: each session that has no standing for a flow through
     * the connection.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideSessionsWithoutStanding(): iterable
    {
        yield 'through another connection' => ['another connection'];

        yield 'signed in with a password' => ['password'];

        yield 'another person\'s' => ['another person'];

        yield 'revoked' => ['revoked'];

        yield 'unknown' => ['unknown'];
    }

    /**
     * Every session without standing is `not_signed_in` as a flow starts,
     * answered and never thrown.
     *
     * @param  string  $case
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideSessionsWithoutStanding')]
    public function testASessionWithoutStandingIsNotSignedInAsAFlowStarts(string $case): void
    {
        $person    = $this->createPerson();
        $sessionId = $this->sessionWithoutStanding($person, $case);

        self::assertSame(SessionStanding::NOT_SIGNED_IN, $this->adapter()->standing(self::referenceOf($person), $sessionId, self::connection()));
    }

    /**
     * Asked as a flow starts, outside any transaction, nothing is locked and
     * nothing is written.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testAFlowsStartLocksAndWritesNothing(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        $person  = $this->createPerson();
        $session = $this->signInThrough($person);
        $before  = $this->stored($session)->getAttributes();

        DB::enableQueryLog();

        self::assertSame(SessionStanding::SIGNED_IN, $this->adapter()->standing(self::referenceOf($person), self::keyOf($session), self::connection()));

        $writes = array_filter(DB::getQueryLog(), static fn (array $query): bool => preg_match(self::WRITES_OR_LOCKS, $query['query']) === 1);

        self::assertSame([], $writes);
        self::assertFalse($this->isLockedElsewhere($session));
        self::assertSame($before, $this->stored($session)->getAttributes());
    }

    /**
     * Inside the redemption's transaction a session established through exactly
     * the link, on the application's guard, stands, and its row is locked last,
     * until the transaction ends.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testTheLockedStandingLocksTheSessionsRowUntilTheTransactionEnds(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        $person  = $this->createPerson();
        $session = $this->signInThrough($person);

        DB::connection(StorageConnection::name())->transaction(function () use ($person, $session): void {

            self::assertFalse($this->isLockedElsewhere($session));
            self::assertSame(SessionStanding::SIGNED_IN, $this->lockedStanding($person, $session));
            self::assertTrue($this->isLockedElsewhere($session));
        });

        self::assertFalse($this->isLockedElsewhere($session));
    }

    /**
     * Rows of `[case]`: each session that has no standing for the redemption
     * through exactly the link, on the application's guard.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideSessionsWithoutLockedStanding(): iterable
    {
        yield 'through another link' => ['another link'];

        yield 'of another application' => ['another application'];

        yield 'through another connection' => ['another connection'];

        yield 'signed in with a password' => ['password'];

        yield 'another person\'s' => ['another person'];

        yield 'revoked' => ['revoked'];

        yield 'unknown' => ['unknown'];
    }

    /**
     * Every session without standing through exactly the link, on the
     * application's guard, is `not_signed_in` to the redemption, answered and
     * never thrown, so SSO refuses it as ineligible.
     *
     * @param  string  $case
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideSessionsWithoutLockedStanding')]
    public function testASessionWithoutLockedStandingIsNotSignedIn(string $case): void
    {
        $person    = $this->createPerson();
        $sessionId = $case === 'another link' ? self::keyOf($this->signInThrough($person, linkId: 'link-2')) : $this->sessionWithoutStanding($person, $case);

        DB::connection(StorageConnection::name())->transaction(function () use ($person, $sessionId): void {

            self::assertSame(SessionStanding::NOT_SIGNED_IN, $this->adapter()->lockedStanding(self::referenceOf($person), $sessionId, self::GUARD, self::connection(), self::LINK));
        });
    }

    /**
     * The locked standing is asked only inside a transaction on the storage
     * connection, which holds the session's row: outside one it could lock
     * nothing, so it throws rather than answer unprotected.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheLockedStandingOutsideATransactionThrows(): void
    {
        $person  = $this->createPerson();
        $session = $this->signInThrough($person);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('inside the redemption\'s transaction');

        $this->lockedStanding($person, $session);
    }

    /**
     * An application that is no guard holding sessions cannot be resolved, so
     * the locked standing throws inside the redemption's transaction (IAM-8.2).
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnApplicationThatIsNoSessionGuardThrows(): void
    {
        $person  = $this->createPerson();
        $session = $this->signInThrough($person);

        try {
            DB::connection(StorageConnection::name())->transaction(function () use ($person, $session): void {
                $this->adapter()->lockedStanding(self::referenceOf($person), self::keyOf($session), 'web', self::connection(), self::LINK);
            });

            self::fail('An application that is no session guard was answered.');
        } catch (UnresolvedReferenceException $exception) {
            self::assertSame(ReferenceKind::GUARD, $exception->kind);
            self::assertSame('web', $exception->application);
        }
    }

    /**
     * An identity reference that names no identity of
     * `laravel-authentication`'s throws, as a flow starts and inside the
     * redemption alike (IAM-8.2).
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnresolvedIdentityThrows(): void
    {
        $person   = $this->createPerson();
        $session  = $this->signInThrough($person);
        $stranger = new IdentityReference(Person::class, '987654');
        $adapter  = $this->adapter();
        $locked   = static fn (): SessionStanding => $adapter->lockedStanding($stranger, self::keyOf($session), self::GUARD, self::connection(), self::LINK);
        $asks     = [
            static fn (): SessionStanding => $adapter->standing($stranger, self::keyOf($session), self::connection()),
            static fn (): SessionStanding => DB::connection(StorageConnection::name())->transaction($locked),
        ];

        foreach ($asks as $ask) {
            try {
                $ask();

                self::fail('An unresolved identity was answered.');
            } catch (UnresolvedReferenceException $exception) {
                self::assertSame(ReferenceKind::IDENTITY, $exception->kind);
            }
        }
    }

    /**
     * The locked standing declares every exception the start's standing does:
     * it resolves the identity and the application's sessions the same way, so
     * an unresolved identity or application refuses it with the same exception
     * (IAM-8.2).
     *
     * @return void
     */
    public function testTheLockedStandingDeclaresWhatTheStandingThrows(): void
    {
        self::assertSame(self::declaredThrows('standing'), self::declaredThrows('lockedStanding'));
    }

    /**
     * The renewal is recorded for the redemption's one write, and nothing is
     * written: the session's authentication time stays as it was.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheRenewalIsRecordedAndNothingIsWritten(): void
    {
        $person   = $this->createPerson();
        $session  = $this->signInThrough($person);
        $before   = $this->stored($session)->getAttributes();
        $at       = CarbonImmutable::now()->addMinute()->startOfSecond();
        $evidence = new AcceptedEvidence(self::SSO_CONNECTION, $at, ['pwd'], null);

        $recorder = $this->openRecorder();

        DB::enableQueryLog();

        $this->adapter()->renewAuthentication(self::referenceOf($person), self::keyOf($session), $at, $evidence);

        $renewal = $recorder->take();

        self::assertSame([], DB::getQueryLog());
        self::assertSame($before, $this->stored($session)->getAttributes());
        self::assertNotNull($renewal);
        self::assertTrue($renewal->identity->is(self::referenceOf($person)));
        self::assertSame(self::keyOf($session), $renewal->sessionId);
        self::assertSame($at, $renewal->authenticatedAt);
        self::assertSame($evidence, $renewal->evidence);
    }

    /**
     * A second renewal in one redemption is a `LogicException`: a session's
     * authentication is renewed once, never twice.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testASecondRenewalIsRefused(): void
    {
        $person  = $this->createPerson();
        $adapter = $this->adapter();

        $this->openRecorder();

        $adapter->renewAuthentication(self::referenceOf($person), 'session-1', CarbonImmutable::now(), null);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A re-authentication renews its session once: a second renewal was recorded in one redemption.');

        $adapter->renewAuthentication(self::referenceOf($person), 'session-1', CarbonImmutable::now(), null);
    }

    /**
     * A renewal asked for while no redemption is open to write it, as when a
     * `reauthenticate` code is admitted through SSO's own admission rather than
     * through `Iam::reauthentications()`, is a `LogicException`, and nothing is
     * recorded or written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARenewalNoRedemptionWouldWriteIsRefused(): void
    {
        $person  = $this->createPerson();
        $session = $this->signInThrough($person);
        $before  = $this->stored($session)->getAttributes();

        try {
            $this->adapter()->renewAuthentication(self::referenceOf($person), self::keyOf($session), CarbonImmutable::now(), null);

            self::fail('A renewal no redemption would write was recorded.');
        } catch (\LogicException $exception) {
            self::assertSame(self::NO_REDEMPTION, $exception->getMessage());
        }

        self::assertFalse($this->app?->make(RenewalRecorder::class)->isHolding());
        self::assertSame($before, $this->stored($session)->getAttributes());
    }

    /**
     * The renewal is recorded in this request's recorder, which the worker
     * reset forgets, never in one the adapter keeps (IAM-8.1).
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheRenewalIsThisRequestsAlone(): void
    {
        $person  = $this->createPerson();
        $adapter = $this->adapter();
        $first   = $this->openRecorder();

        $adapter->renewAuthentication(self::referenceOf($person), 'session-1', CarbonImmutable::now(), null);

        $this->app?->forgetScopedInstances();

        $second = $this->openRecorder();

        $adapter->renewAuthentication(self::referenceOf($person), 'session-2', CarbonImmutable::now(), null);

        self::assertNotSame($first, $second);
        self::assertSame('session-1', $first->take()?->sessionId);
        self::assertSame('session-2', $second->take()?->sessionId);
    }

    /**
     * Declare a second guard holding sessions of the same people, which allows
     * the `external_provider` method too.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        Config::set('auth.guards.' . self::ADMIN, ['driver' => 'jwt', 'provider' => 'people', 'application' => ['methods' => ['external_provider']]]);
    }

    /**
     * This request's renewal recorder, opened as a redemption opens it.
     *
     * @return \SineMacula\Laravel\Iam\Sso\RenewalRecorder
     */
    private function openRecorder(): RenewalRecorder
    {
        $recorder = $this->app?->make(RenewalRecorder::class);

        self::assertInstanceOf(RenewalRecorder::class, $recorder);

        $recorder->open();

        return $recorder;
    }

    /**
     * The adapter, as the container builds it.
     *
     * @return \SineMacula\Laravel\Iam\Sso\ReauthenticationSessionsAdapter
     */
    private function adapter(): ReauthenticationSessionsAdapter
    {
        $adapter = $this->app?->make(ReauthenticationSessionsAdapter::class);

        self::assertInstanceOf(ReauthenticationSessionsAdapter::class, $adapter);

        return $adapter;
    }

    /**
     * The session's locked standing through the tests' connection and link, on
     * the guard.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return \SineMacula\Laravel\Sso\Flows\Enums\SessionStanding
     */
    private function lockedStanding(Person $person, EloquentSession&Model $session): SessionStanding
    {
        return $this->adapter()->lockedStanding(self::referenceOf($person), self::keyOf($session), self::GUARD, self::connection(), self::LINK);
    }

    /**
     * The id of a session of the case's kind, which has no standing for the
     * person through the tests' connection.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  string  $case
     * @return string
     *
     * @throws \Throwable
     */
    private function sessionWithoutStanding(Person $person, string $case): string
    {
        $session = match ($case) {
            'another connection'  => $this->signInThrough($person, 'connection-2'),
            'another application' => $this->signInThrough($person, guard: self::ADMIN),
            'password'            => $this->signIn($person)->record,
            'another person'      => $this->signInThrough($this->createPerson()),
            'revoked'             => $this->revoked($this->signInThrough($person)),
            default               => null,
        };

        return $session === null ? '999999' : self::keyOf($session);
    }

    /**
     * The session, once revoked.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession
     */
    private function revoked(EloquentSession&Model $session): EloquentSession&Model
    {
        $session->newQuery()->whereKey($session->getKey())->update([$session->getRevokedAtName() => $session->fromDateTime(CarbonImmutable::now())]);

        return $session;
    }

    /**
     * The session as it is stored now.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return \Illuminate\Database\Eloquent\Model
     */
    private function stored(EloquentSession&Model $session): Model
    {
        $stored = $session->newQuery()->find($session->getKey());

        self::assertInstanceOf(Model::class, $stored);

        return $stored;
    }

    /**
     * The connection SSO names: the tests' own.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\SsoConnection
     */
    private static function connection(): SsoConnection
    {
        $connection = \Mockery::mock(SsoConnection::class);

        $connection->allows('getConnectionId')->andReturn(self::SSO_CONNECTION);

        return $connection;
    }

    /**
     * The exceptions the adapter's method declares it throws, sorted.
     *
     * @param  string  $method
     * @return list<string>
     *
     * @throws \ReflectionException
     */
    private static function declaredThrows(string $method): array
    {
        preg_match_all('/@throws\s+(\S+)/', (string) (new \ReflectionMethod(ReauthenticationSessionsAdapter::class, $method))->getDocComment(), $declared);

        $throws = $declared[1];

        sort($throws);

        return $throws;
    }
}
