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
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Models\SessionProof;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\ExternalReauthenticationRefusedException;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Sso\ExternalResults;
use SineMacula\Laravel\Iam\Sso\IdentityReferences;
use SineMacula\Laravel\Iam\Sso\ReauthenticationSessionsAdapter;
use SineMacula\Laravel\Iam\Sso\RenewalRecorder;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Flows\Enums\SessionStanding;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Testing\Seams\Concerns\ReauthenticationSessionsContract;
use Tests\Concerns\FindsLockedSessions;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Concerns\SignsInThroughLinks;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * Integration tests for SSO's reauthentication sessions adapter.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReauthenticationSessionsAdapter::class)]
final class ReauthenticationSessionsAdapterTest extends TestCase
{
    use FindsLockedSessions, MigratesMembers, ReauthenticationSessionsContract, RunsAtIsolationLevels, SignsInPeople, SignsInThroughLinks;

    /** @var string What a renewal asked for while no redemption is open to write it is. */
    private const string NO_REDEMPTION = 'SSO asked for a renewal no redemption would write: a re-authentication is redeemed through Iam::reauthentications().';

    /** @var string A second guard holding sessions, which people sign in on through the same connections. */
    private const string ADMIN = 'admin';

    /** @var string A statement that writes, or a read that locks. */
    private const string WRITES_OR_LOCKS = '/^\s*(insert|update|delete)|for update|for share|lock in share mode/i';

    /** @var list<\Tests\Fixtures\Models\Person> The two people the contract kit signs in. */
    private array $people = [];

    /** @var array<string, string> The link the contract kit signed each session in through. */
    private array $linkOf = [];

    /**
     * A session stands as a flow starts only for its own application.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionStandsOnlyForItsOwnApplicationAsAFlowStarts(): void
    {
        $person  = $this->createPerson();
        $session = $this->signInThrough($person, guard: self::ADMIN);

        self::assertSame(SessionStanding::SIGNED_IN, $this->adapter()->standing(self::referenceOf($person), self::keyOf($session), self::ADMIN, self::connection()));
        self::assertSame(SessionStanding::NOT_SIGNED_IN, $this->adapter()->standing(self::referenceOf($person), self::keyOf($session), self::GUARD, self::connection()));
    }

    /**
     * Rows of `[case]`: each session with no standing through the connection.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideSessionsWithoutStanding(): iterable
    {
        yield 'through another connection' => ['another connection'];

        yield 'signed in with a password' => ['password'];

        yield 'unknown' => ['unknown'];
    }

    /**
     * A session without standing is `not_signed_in` as a flow starts.
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

        self::assertSame(SessionStanding::NOT_SIGNED_IN, $this->adapter()->standing(self::referenceOf($person), $sessionId, self::GUARD, self::connection()));
    }

    /**
     * A flow's start locks nothing and writes nothing.
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

        self::assertSame(SessionStanding::SIGNED_IN, $this->adapter()->standing(self::referenceOf($person), self::keyOf($session), self::GUARD, self::connection()));

        $writes = array_filter(DB::getQueryLog(), static fn (array $query): bool => preg_match(self::WRITES_OR_LOCKS, $query['query']) === 1);

        self::assertSame([], $writes);
        self::assertFalse($this->isLockedElsewhere($session));
        self::assertSame($before, $this->stored($session)->getAttributes());
    }

    /**
     * The locked standing locks the session's row until the transaction ends.
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
     * Rows of `[case]`: each session with no standing through exactly the link.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideSessionsWithoutLockedStanding(): iterable
    {
        yield 'of another application' => ['another application'];

        yield 'through another connection' => ['another connection'];

        yield 'signed in with a password' => ['password'];

        yield 'revoked' => ['revoked'];

        yield 'unknown' => ['unknown'];
    }

    /**
     * A session without locked standing is `not_signed_in`, never thrown.
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
        $sessionId = $this->sessionWithoutStanding($person, $case);

        DB::connection(StorageConnection::name())->transaction(function () use ($person, $sessionId): void {

            self::assertSame(SessionStanding::NOT_SIGNED_IN, $this->adapter()->lockedStanding(self::referenceOf($person), $sessionId, self::GUARD, self::connection(), self::LINK));
        });
    }

    /**
     * The locked standing throws outside a transaction.
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
     * An application that is no session guard throws.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnApplicationThatIsNoSessionGuardThrows(): void
    {
        $person  = $this->createPerson();
        $session = $this->signInThrough($person);
        $adapter = $this->adapter();
        $locked  = static fn (): SessionStanding => $adapter->lockedStanding(self::referenceOf($person), self::keyOf($session), 'web', self::connection(), self::LINK);
        $asks    = [
            static fn (): SessionStanding => $adapter->standing(self::referenceOf($person), self::keyOf($session), 'web', self::connection()),
            static fn (): SessionStanding => DB::connection(StorageConnection::name())->transaction($locked),
        ];

        foreach ($asks as $ask) {
            try {
                $ask();

                self::fail('An application that is no session guard was answered.');
            } catch (UnresolvedReferenceException $exception) {
                self::assertSame(ReferenceKind::GUARD, $exception->kind);
                self::assertSame('web', $exception->application);
            }
        }
    }

    /**
     * An identity reference naming no identity throws.
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
            static fn (): SessionStanding => $adapter->standing($stranger, self::keyOf($session), self::GUARD, self::connection()),
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
     * The locked standing declares every exception the standing does.
     *
     * @return void
     */
    public function testTheLockedStandingDeclaresWhatTheStandingThrows(): void
    {
        self::assertSame(self::declaredThrows('standing'), self::declaredThrows('lockedStanding'));
    }

    /**
     * The renewal is recorded and nothing is written.
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
     * A second renewal in one redemption is a `LogicException`.
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
     * A renewal no redemption would write is a `LogicException`.
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
     * The renewal is recorded in this request's recorder alone.
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
     * The adapter as a redemption hands it to SSO, with its recorder open.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions
     */
    #[\Override]
    protected function reauthenticationSessions(): ReauthenticationSessions
    {
        $this->openRecorder();

        return $this->adapter();
    }

    /**
     * The tests' connection.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\SsoConnection
     */
    #[\Override]
    protected function reauthenticationConnection(): SsoConnection
    {
        return self::connection();
    }

    /**
     * The guard the sessions are signed in on.
     *
     * @return string
     */
    #[\Override]
    protected function reauthenticationApplication(): string
    {
        return self::GUARD;
    }

    /**
     * Two people, the same on every call.
     *
     * @return array{0: \SineMacula\Laravel\Sso\Identities\IdentityReference, 1: \SineMacula\Laravel\Sso\Identities\IdentityReference}
     */
    #[\Override]
    protected function reauthenticationIdentities(): array
    {
        if ($this->people === []) {
            $this->people = [$this->createPerson(), $this->createPerson()];
        }

        return [self::referenceOf($this->people[0]), self::referenceOf($this->people[1])];
    }

    /**
     * Sign the person in through a new link at the time given.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \Carbon\CarbonImmutable  $authenticatedAt
     * @return array{0: string, 1: string}
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function signInForReauthentication(IdentityReference $identity, CarbonImmutable $authenticatedAt): array
    {
        $person = (new IdentityReferences)->identity($identity);
        $linkId = 'kit-link-' . (count($this->linkOf) + 1);
        $now    = CarbonImmutable::now();

        self::assertInstanceOf(Person::class, $person);

        $this->travelTo($authenticatedAt);

        $session = $this->signInThrough($person, linkId: $linkId);

        $this->travelTo($now);

        $this->linkOf[self::keyOf($session)] = $linkId;

        return [self::keyOf($session), $linkId];
    }

    /**
     * Revoke the session.
     *
     * @param  string  $sessionId
     * @return void
     */
    #[\Override]
    protected function revokeReauthenticationSession(string $sessionId): void
    {
        $this->revoked(Session::query()->findOrFail($sessionId));
    }

    /**
     * The newest time the session's proofs record.
     *
     * @param  string  $sessionId
     * @return \Carbon\CarbonImmutable
     */
    #[\Override]
    protected function sessionAuthenticatedAt(string $sessionId): CarbonImmutable
    {
        $proof = SessionProof::query()->where('session_id', $sessionId)->latest('authenticated_at')->firstOrFail();

        return CarbonImmutable::instance($proof->authenticated_at);
    }

    /**
     * Write the renewal recorded, as the redemption writes it.
     *
     * @param  string  $sessionId
     * @return void
     *
     * @throws \SineMacula\Laravel\Iam\Exceptions\ExternalReauthenticationRefusedException
     * @throws \Throwable
     */
    protected function completeRenewal(string $sessionId): void
    {
        $recorder = $this->app?->make(RenewalRecorder::class);

        self::assertInstanceOf(RenewalRecorder::class, $recorder);

        $renewal = $recorder->take() ?? self::fail('No renewal was recorded.');
        $person  = (new IdentityReferences)->identity($renewal->identity);
        $linkId  = $this->linkOf[$sessionId] ?? self::fail('The kit signed no session in under that id.');

        self::assertSame($sessionId, $renewal->sessionId);
        self::assertInstanceOf(Person::class, $person);

        $records    = $this->admit($person, linkId: $linkId);
        $redemption = $records->matching(self::SSO_CONNECTION, self::ISSUER, self::subjectOf($person), null) ?? self::fail('No redemption was admitted.');

        try {
            $token = $this->sessions()->reauthenticateExternally($sessionId, ExternalResults::renewing($redemption, $renewal), self::client());
        } finally {
            $records->forget();
        }

        if ($token->isFailed()) {
            throw ExternalReauthenticationRefusedException::for($token);
        }
    }

    /**
     * Declare a second session guard of the same people.
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
     * The session's locked standing through the tests' connection and link.
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
     * The id of a session of the case's kind, without standing.
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
