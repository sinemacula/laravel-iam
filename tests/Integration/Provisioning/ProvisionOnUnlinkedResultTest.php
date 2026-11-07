<?php

declare(strict_types = 1);

namespace Tests\Integration\Provisioning;

use Carbon\CarbonImmutable;
use Illuminate\Database\Connection as DatabaseConnection;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Events\EventContext as AuthenticationEventContext;
use SineMacula\Laravel\Authentication\Events\ExternalResultUnlinked;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Provisioning\CommittedReads;
use SineMacula\Laravel\Iam\Provisioning\ProvisioningSettings;
use SineMacula\Laravel\Iam\Provisioning\ProvisionOnUnlinkedResult;
use SineMacula\Laravel\Iam\Provisioning\RefusedLink;
use SineMacula\Laravel\Iam\Sso\IdentityReferences;
use SineMacula\Laravel\Iam\Sso\SsoSeams;
use SineMacula\Laravel\Iam\Storage\StorageConnection;
use SineMacula\Laravel\Iam\Tenancy\ScopeWidenings;
use SineMacula\Laravel\Iam\Testing\FakeProvisioner;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
use SineMacula\Laravel\Sso\Connections\ConnectionLifecycle;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Contracts\LinkStorage;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\FlowFailed;
use SineMacula\Laravel\Sso\Events\HandoffIssued;
use SineMacula\Laravel\Sso\Events\LinkCreated;
use SineMacula\Laravel\Sso\Events\LinkSuspended;
use SineMacula\Laravel\Sso\Events\ResultUnlinked;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Http\ClientContext as SsoClientContext;
use SineMacula\Laravel\Sso\Linking\IdentityLock;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\IdentityGuard;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Provisioning\Enums\ProvisioningStatus;
use SineMacula\Laravel\Sso\Provisioning\ProvisioningHelper;
use SineMacula\Laravel\Sso\Responses\CompletionResponses;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use SineMacula\Laravel\Sso\Testing\HandoffRedirect;
use Tests\Concerns\MigratesSso;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Provisioning\ProvisionedMembership;
use Tests\Fixtures\Provisioning\ProvisionsPeople;
use Tests\Fixtures\Provisioning\QueuedProvisioning;
use Tests\TestCase;

/**
 * Integration tests for provisioning a new identity for a `sign_in` SSO found
 * unlinked (IAM-7.1), through SSO's whole flow against a fake OpenID provider,
 * against the provisioning checks of SSO's guide to this package: one
 * synchronous listener creates a new identity, its membership of the
 * connection's tenant and the link, in one transaction, in that order, after
 * SSO's scope widening, and the sign-in then redeems as the new person; an
 * identity that is not new (an existing person, or one inserted before the call
 * and kept), a helper's refusal and anything thrown roll all three back; the
 * grant is used once and the transaction never retried; a
 * subject another request links meanwhile leaves no provisioned person behind;
 * what the listener committed stands after the completion fails, and the next
 * sign-in resolves through the link; a queued listener fails loudly and
 * provisions nothing; `laravel-authentication`'s informational unlinked result
 * provisions nothing; and with no provisioner nothing is provisioned.
 *
 * Each scenario that commits or rolls back runs at the connection's own level
 * on every engine, then at READ COMMITTED and REPEATABLE READ on MySQL and
 * PostgreSQL. The subject linked elsewhere meanwhile needs a second connection
 * committing while the listener's transaction is open, which SQLite's single
 * writer cannot give, so it runs on MySQL and PostgreSQL at both levels only.
 * The retry, a refusal before any transaction opens (a queued listener, the
 * informational event, no provisioner) and the absent provisioner run at the
 * connection's own level alone, since no level changes what they read.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProvisionOnUnlinkedResult::class)]
#[CoversClass(CommittedReads::class)]
#[CoversClass(ProvisioningSettings::class)]
#[CoversClass(RefusedLink::class)]
#[CoversClass(ScopeWidenings::class)]
final class ProvisionOnUnlinkedResultTest extends TestCase
{
    use MigratesSso, RunsAtIsolationLevels, RunsSsoFlows, SignsInPeople;

    /** @var \ArrayObject<int, object> What SSO reported of each flow, in order. */
    private \ArrayObject $reported;

    /** @var ?string The verifier the client kept from the last flow `complete()` started. */
    private ?string $verifier = null;

    /** @var list<array{step: string, level: int, guarded: bool, linked: bool}> What the provisioner saw at each step. */
    private array $observed = [];

    /**
     * Arrange SSO, and listen for what each flow reports.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeSso();

        $reported       = new \ArrayObject;
        $this->reported = $reported;

        Event::listen([FlowFailed::class, HandoffIssued::class, LinkCreated::class, LinkSuspended::class], static function (object $event) use ($reported): void {
            $reported->append($event);
        });
    }

    /**
     * An unlinked sign-in is provisioned a new person, a membership of the
     * connection's tenant and an active link of `provisioning` origin, and is
     * issued a handoff that signs the new person in; `LinkCreated` follows the
     * listener's commit and `HandoffIssued` the completion's.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAnUnlinkedSignInIsProvisionedAndSignsTheNewPersonIn(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $this->provisionPeople();

        $handoff = $this->handoff();
        $person  = $this->onlyProvisioned();
        $link    = Link::query()->sole();

        self::assertSame($person->getMorphClass(), $link->identity_type);
        self::assertSame((string) $person->id, $link->identity_id);
        self::assertSame($this->connectionId, $link->connection_id);
        self::assertSame(LinkState::ACTIVE, $link->state);
        self::assertSame(LinkOrigin::PROVISIONING, $link->provenance);
        self::assertSame([self::TENANT], ProvisionedMembership::query()->where('person_id', $person->id)->pluck('tenant_id')->all());

        $signedIn = Iam::signIns()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, new SignInContext(self::client()));

        self::assertInstanceOf(SignInResult::class, $signedIn);
        self::assertTrue($signedIn->isSignedIn());
        self::assertSessionOf($person, $signedIn);

        $created = $this->reportedOf(LinkCreated::class);

        self::assertCount(1, $created);
        self::assertSame(LinkOrigin::PROVISIONING, $created[0]->origin);
        self::assertSame(self::CLIENT_IP, $created[0]->context->ip);
        self::assertSame(self::CLIENT_AGENT, $created[0]->context->userAgent);
        self::assertCount(1, $this->reportedOf(HandoffIssued::class));
        self::assertSame([], $this->reportedOf(FlowFailed::class));
    }

    /**
     * Inside the one transaction, in order: the identity is inserted before
     * SSO's scope widening takes its guard, the guard is held before the
     * membership is written, and the link is written after the membership.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testEachWriteComesInOrderInsideOneTransaction(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $this->provisionPeople(function (string $step, Person $person): void {

            $reference = (new IdentityReferences)->reference($person);

            $this->observed[] = [
                'step'    => $step,
                'level'   => DB::connection()->transactionLevel(),
                'guarded' => IdentityGuard::query()->where('identity_hash', IdentityLock::digest($reference))->exists(),
                'linked'  => Link::query()->where('identity_id', $reference->id)->exists(),
            ];
        });

        $this->handoff();

        self::assertCount(2, $this->observed);
        self::assertSame(['step' => 'identity', 'guarded' => false, 'linked' => false], array_diff_key($this->observed[0], ['level' => true]));
        self::assertSame(['step' => 'membership', 'guarded' => true, 'linked' => false], array_diff_key($this->observed[1], ['level' => true]));
        self::assertGreaterThan(0, $this->observed[0]['level']);
        self::assertGreaterThan(0, $this->observed[1]['level']);
        self::assertSame(0, DB::connection()->transactionLevel());
        self::assertTrue(Link::query()->where('identity_id', (string) $this->onlyProvisioned()->id)->exists());
    }

    /**
     * The listener's one attempt reads committed rows on PostgreSQL and MySQL,
     * whatever level the connection runs at, as the transaction itself reports
     * it (MySQL's `@@transaction_isolation` reports the session's), and the
     * connection's own level is left as it was for every later transaction.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testTheAttemptReadsCommittedRows(string $level): void
    {
        self::runAtIsolationLevel($level);

        $read = [];

        $this->provisionPeople(static function (string $step) use (&$read): void {

            $read[$step] = DB::connection()->getDriverName() === 'pgsql'
                ? DB::connection()->scalar('select current_setting(\'transaction_isolation\')')
                : DB::connection()->scalar('select isolation_level from performance_schema.events_transactions_current where thread_id = ps_current_thread_id()');
        });

        $this->handoff();

        $postgres = DB::connection()->getDriverName() === 'pgsql';
        $expected = $postgres ? 'read committed' : 'READ COMMITTED';
        $own      = $postgres ? 'select current_setting(\'transaction_isolation\')' : 'select @@transaction_isolation';

        self::assertSame(['identity' => $expected, 'membership' => $expected], $read);
        self::assertSame($postgres ? $level : str_replace(' ', '-', strtoupper($level)), DB::connection()->scalar($own));
    }

    /**
     * Rows of `[driver, the transaction level the setting is made at]`: on
     * PostgreSQL inside the transaction the listener opened, before anything is
     * written in it; on MySQL and MariaDB with none open, before it begins.
     *
     * @return iterable<string, array{0: string, 1: int}>
     */
    public static function provideSettingMoments(): iterable
    {
        yield 'PostgreSQL' => ['pgsql', 1];

        yield 'MySQL' => ['mysql', 0];

        yield 'MariaDB' => ['mariadb', 0];
    }

    /**
     * The listener's attempt is set to read committed rows before anything is
     * written in it, at the moment the engine takes it: here with the storage
     * connection reporting the driver given to the setting alone, so the
     * setting is made on every engine the suite runs on, and recorded, with the
     * transaction level it was made at, rather than run.
     *
     * @param  string  $driver
     * @param  int  $at
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideSettingMoments')]
    public function testTheAttemptIsSetBeforeAnythingIsWritten(string $driver, int $at): void
    {
        /** @var list<array{0: string, 1: int}> $set */
        $set        = [];
        $seen       = [];
        $connection = \Mockery::mock(DatabaseConnection::class);
        $database   = \Mockery::mock(DatabaseManager::class);
        $app        = $this->app ?? self::fail('The application has not booted.');

        $connection->allows('getDriverName')->andReturn($driver);
        $connection->allows('transactionLevel')->andReturnUsing(static fn (): int => DB::connection()->transactionLevel());
        $connection->allows('statement')->andReturnUsing(static function (string $sql) use (&$set): bool {
            $set[] = [$sql, DB::connection()->transactionLevel()];

            return true;
        });
        $database->allows('connection')->andReturn($connection);

        $app->instance(CommittedReads::class, new CommittedReads($database, $app->make(StorageConnection::class)));

        $this->provisionPeople(static function (string $step) use (&$set, &$seen): void {
            $seen[$step] = $set;
        });

        $this->handoff();

        self::assertSame(['identity' => [[CommittedReads::STATEMENT, $at]], 'membership' => [[CommittedReads::STATEMENT, $at]]], $seen);
    }

    /**
     * SSO's scope widening for the new person is reported for the completion's
     * client: a link by a verified domain the person holds in another tenant's
     * connection by the time it runs (written here by the provisioner, in the
     * listener's transaction) is suspended, and SSO reports the suspension with
     * the IP address and user agent the completion carried.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testTheWideningIsReportedForTheCompletionsClient(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $other = $this->makeConnection('tenant-2');

        $this->provisionPeople(static function (string $step, Person $person) use ($other): void {

            if ($step !== 'identity') {
                return;
            }

            self::linkByDomain($person, $other);
        });

        $this->handoff();

        $suspended = $this->reportedOf(LinkSuspended::class);

        self::assertCount(1, $suspended);
        self::assertSame($other, $suspended[0]->context->connectionId);
        self::assertSame(self::CLIENT_IP, $suspended[0]->context->ip);
        self::assertSame(self::CLIENT_AGENT, $suspended[0]->context->userAgent);
        self::assertSame(LinkState::SUSPENDED, Link::query()->where('connection_id', $other)->sole()->state);
    }

    /**
     * A provisioner that answers an existing person, as one that looked them up
     * by an attribute would, is refused before anything is written: the
     * completion ends as a server error, no membership or link is made, and the
     * existing person is left as they were.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAnExistingIdentityIsNeverProvisioned(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $existing = Person::query()->findOrFail($this->createPerson('existing@people.test')->id);
        $fake     = FakeProvisioner::fake(static fn (): Identity => $existing);

        $thrown = self::thrownBy(fn (): HandoffRedirect => $this->complete());

        self::assertInstanceOf(\LogicException::class, $thrown);
        self::assertStringContainsString('provisioning always creates a new identity', $thrown->getMessage());
        self::assertSame([], $fake->memberships());
        self::assertSame(0, Link::query()->count());
        self::assertSame(0, IdentityGuard::query()->count());
        self::assertSame(1, Person::query()->count());
        self::assertSame([], $this->reportedOf(LinkCreated::class));
        self::assertSame(0, DB::connection()->transactionLevel());
    }

    /**
     * A provisioner that answers a person it inserted before it was asked, and
     * kept, is refused as one that found the person is: the listener witnessed
     * no insertion of that person during the call. So is a person inserted
     * during the call with its model events off, which no insertion witnessed.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAnIdentityInsertedBeforeTheCallIsNeverProvisioned(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $kept = Person::query()->create(['name' => 'Kept', 'email' => 'kept@people.test']);

        self::assertTrue($kept->wasRecentlyCreated);

        $fake   = FakeProvisioner::fake(static fn (): Identity => $kept);
        $thrown = self::thrownBy(fn (): HandoffRedirect => $this->complete());

        self::assertInstanceOf(\LogicException::class, $thrown);
        self::assertStringContainsString('provisioning always creates a new identity', $thrown->getMessage());
        self::assertSame([], $fake->memberships());

        FakeProvisioner::fake(static fn (): Identity => Person::query()->createQuietly(['name' => 'Quiet', 'email' => 'quiet@people.test']));

        $thrown = self::thrownBy(fn (): HandoffRedirect => $this->complete());

        self::assertInstanceOf(\LogicException::class, $thrown);
        self::assertSame(['kept@people.test'], Person::query()->pluck('email')->all());
        self::assertSame(0, Link::query()->count());
        self::assertSame(0, IdentityGuard::query()->count());
        self::assertSame(0, DB::connection()->transactionLevel());
    }

    /**
     * A refusal from SSO's provisioning helper (here the verified response's
     * deadline passing while the listener ran) rolls the identity and its
     * membership back with the link the helper never wrote; the listener
     * returns, and the completion ends as a failed flow, never with a handoff.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testARefusedLinkRollsBackTheIdentityAndTheMembership(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $this->provisionPeople(function (string $step): void {

            if ($step !== 'membership') {
                return;
            }

            $this->travel(301)->seconds();
        });

        $redirect = $this->complete();

        self::assertFalse($redirect->hasCode());
        self::assertSame(0, Person::query()->count());
        self::assertSame(0, ProvisionedMembership::query()->count());
        self::assertSame(0, Link::query()->count());
        self::assertSame(0, IdentityGuard::query()->count());
        self::assertSame([], $this->reportedOf(LinkCreated::class));
        self::assertCount(1, $this->reportedOf(FlowFailed::class));
        self::assertSame(0, DB::connection()->transactionLevel());
    }

    /**
     * Anything the provisioner throws once the identity is inserted and its
     * guard taken rolls every write back and propagates, ending the completion
     * as a server error.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAnExceptionRollsBackEveryWrite(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $refusal = new \RuntimeException('No membership for this tenant.');

        $this->provisionPeople(static function (string $step) use ($refusal): void {

            if ($step === 'membership') {
                throw $refusal;
            }
        });

        self::assertSame($refusal, self::thrownBy(fn (): HandoffRedirect => $this->complete()));
        self::assertSame(0, Person::query()->count());
        self::assertSame(0, ProvisionedMembership::query()->count());
        self::assertSame(0, Link::query()->count());
        self::assertSame(0, IdentityGuard::query()->count());
        self::assertSame([], $this->reportedOf(HandoffIssued::class));
        self::assertSame(0, DB::connection()->transactionLevel());
    }

    /**
     * Another request links the subject to someone else, through SSO's link
     * storage, which raises the connection's links version, committing on
     * another connection once the listener has inserted its person: SSO's
     * helper, reading the subject's link under its lock, refuses
     * `subject_already_linked`, the listener rolls its person and membership
     * back and returns, and the completion resolves the subject anew, handing
     * off for the person the other link names. On PostgreSQL at REPEATABLE READ
     * too, where the listener's one attempt reads committed rows rather than
     * fail to serialise on the connection's row the other link wrote.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testASubjectLinkedElsewhereMeanwhileLeavesNoProvisionedPerson(string $level): void
    {
        self::runAtIsolationLevel($level);

        $other = $this->createPerson('other@people.test');

        $this->provisionPeople(function (string $step, Person $person, VerifiedResult $result) use ($other): void {

            if ($step !== 'identity') {
                return;
            }

            $this->linkElsewhere($result, $other);
        });

        $redirect = $this->complete();

        self::assertTrue($redirect->hasCode());
        self::assertSessionOf($other, $this->signInWith($redirect));

        self::assertSame([$other->id], Person::query()->get()->map(static fn (Person $person): int => $person->id)->all());
        self::assertSame(0, ProvisionedMembership::query()->count());
        self::assertSame(1, Link::query()->count());
        self::assertSame((string) $other->id, Link::query()->sole()->identity_id);
    }

    /**
     * Another person's first sign-in through the same connection links them,
     * through SSO's link storage, committing on another connection once the
     * listener has inserted its person: the listener still provisions its own
     * person and links them, on PostgreSQL at REPEATABLE READ as at every other
     * level, and the sign-in signs the new person in.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testAnotherSubjectLinkedMeanwhileStillProvisions(string $level): void
    {
        self::runAtIsolationLevel($level);

        $other = $this->createPerson('other@people.test');

        $this->provisionPeople(function (string $step, Person $person, VerifiedResult $result) use ($other): void {

            if ($step !== 'identity') {
                return;
            }

            $this->linkElsewhere($result, $other, 'another-subject');
        });

        $redirect = $this->complete();

        self::assertTrue($redirect->hasCode(), (string) $redirect->error);

        $person = Person::query()->whereKeyNot($other->id)->sole();

        self::assertSessionOf($person, $this->signInWith($redirect));
        self::assertSame([self::TENANT], ProvisionedMembership::query()->where('person_id', $person->id)->pluck('tenant_id')->all());
        self::assertSame(2, Link::query()->count());
        self::assertSame(LinkOrigin::PROVISIONING, Link::query()->where('identity_id', (string) $person->id)->sole()->provenance);
    }

    /**
     * The grant is spent by the listener: a second listener of the same event
     * is refused `grant_invalid`, and the sign-in still finishes through the
     * link the first made.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testTheGrantIsUsedOnce(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $this->provisionPeople();

        $second = null;

        Event::listen(ResultUnlinked::class, function (ResultUnlinked $event) use (&$second): void {

            $person    = Person::query()->create(['name' => 'Second', 'email' => 'second@people.test']);
            $reference = (new IdentityReferences)->reference($person);
            $second    = $this->app?->make(ProvisioningHelper::class)->link($event->grant, $event->result, $reference, new SsoClientContext(null, null));
        });

        $this->handoff();

        self::assertSame(ProvisioningStatus::GRANT_INVALID, $second?->status);
        self::assertSame(1, Link::query()->count());
    }

    /**
     * The provisioning transaction is attempted once, never retried after a
     * concurrency failure, since the grant allows one use: the failure
     * propagates, the provisioner having been asked once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheTransactionIsNeverRetried(): void
    {
        $asked   = 0;
        $failure = new QueryException(self::CONNECTION, 'insert into iam_people', [], new \PDOException('Serialization failure', 40001));

        $failure->errorInfo = ['40001', 1213, 'Deadlock found when trying to get lock'];

        FakeProvisioner::fake(static function () use (&$asked, $failure): Identity {
            $asked++;

            throw $failure;
        });

        self::assertSame($failure, self::thrownBy(fn (): HandoffRedirect => $this->complete()));
        self::assertSame(1, $asked);
        self::assertSame(0, Link::query()->count());
    }

    /**
     * Once the listener has committed, a completion that then fails (the
     * connection disabled before its final step) leaves the identity, its
     * membership and the link made; the next sign-in through the connection,
     * once it is enabled again, resolves through the link to the same person
     * and is not offered for provisioning again.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testWhatTheListenerCommittedStandsAfterALaterFailure(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $this->provisionPeople();

        Event::listen(ResultUnlinked::class, function (): void {
            $this->app?->make(ConnectionLifecycle::class)->disable(self::TENANT, $this->connectionId, self::ssoClient());
        });

        $failed = $this->complete();

        self::assertFalse($failed->hasCode());
        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE->value, $failed->error);

        $person = $this->onlyProvisioned();

        self::assertSame(1, Link::query()->where('identity_id', (string) $person->id)->count());
        self::assertSame([self::TENANT], ProvisionedMembership::query()->where('person_id', $person->id)->pluck('tenant_id')->all());

        Event::forget(ResultUnlinked::class);

        self::assertTrue($this->app?->make(ConnectionService::class)->enable(self::TENANT, $this->connectionId, self::ssoClient())->isSucceeded());

        $handoff  = $this->handoff();
        $signedIn = Iam::signIns()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, new SignInContext(self::client()));

        self::assertInstanceOf(SignInResult::class, $signedIn);
        self::assertSessionOf($person, $signedIn);
        self::assertSame(1, Person::query()->count());
        self::assertSame(1, ProvisionedMembership::query()->count());
    }

    /**
     * A queued provisioning listener fails loudly, as SSO's event refuses to be
     * serialised, and provisions nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAQueuedListenerFailsLoudlyAndProvisionsNothing(): void
    {
        QueuedProvisioning::$handled = 0;

        Event::listen(ResultUnlinked::class, QueuedProvisioning::class);

        $thrown = self::thrownBy(fn (): HandoffRedirect => $this->complete());

        self::assertTrue(self::isOrFollows($thrown, 'The unlinked-result event cannot be serialised'));
        self::assertSame(0, QueuedProvisioning::$handled);
        self::assertSame(0, Person::query()->count());
        self::assertSame(0, Link::query()->count());
    }

    /**
     * With the SSO capability's adapters off and a provisioner configured, the
     * listener still provisions, but SSO's provisioning helper refuses a linker
     * not backed by its link storage with a `LogicException`, which rolls the
     * identity and the membership back: nothing is written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    #[WithConfig(SsoSeams::SWITCH, false, defer: false)]
    public function testWithTheSsoAdaptersOffTheHelpersRefusalWritesNothing(): void
    {
        $this->provisionPeople();

        $thrown = self::thrownBy(fn (): HandoffRedirect => $this->complete());

        self::assertInstanceOf(\LogicException::class, $thrown);
        self::assertTrue(self::isOrFollows($thrown, 'LinkStorage'), $thrown->getMessage());
        self::assertSame(0, Person::query()->count());
        self::assertSame(0, ProvisionedMembership::query()->count());
        self::assertSame(0, Link::query()->count());
        self::assertSame(0, IdentityGuard::query()->count());
        self::assertSame(0, DB::connection()->transactionLevel());
    }

    /**
     * With no provisioner bound or named, nothing is provisioned: the sign-in
     * ends as SSO's `unlinked`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithNoProvisionerNothingIsProvisioned(): void
    {
        $redirect = $this->complete();

        self::assertFalse($redirect->hasCode());
        self::assertSame(FailureReason::UNLINKED->value, $redirect->error);
        self::assertSame(0, Person::query()->count());
        self::assertSame(0, Link::query()->count());
    }

    /**
     * `laravel-authentication`'s informational unlinked result provisions
     * nothing: only SSO's is listened to.
     *
     * @return void
     */
    public function testAuthenticationsUnlinkedResultProvisionsNothing(): void
    {
        $fake = FakeProvisioner::fake(static fn (): Identity => self::fail('Provisioned on the informational event.'));

        Event::dispatch(new ExternalResultUnlinked(new AuthenticationEventContext(self::GUARD, self::client()), 'https://idp.example.test'));

        self::assertSame([], $fake->identities());
        self::assertSame(0, Link::query()->count());
    }

    /**
     * Bind the fixture provisioner, looking at the database at each step with
     * the closure given.
     *
     * @param  ?\Closure(string, \Tests\Fixtures\Models\Person, \SineMacula\Laravel\Sso\Results\VerifiedResult): void  $observe
     * @return void
     */
    private function provisionPeople(?\Closure $observe = null): void
    {
        $this->app?->instance(ProvisionsPeople::class, new ProvisionsPeople($observe));

        $this->app?->make('config')->set(ProvisioningSettings::KEY, ProvisionsPeople::class);
    }

    /**
     * Link the result's subject, or the other subject given, to the person
     * given, as another request would, through SSO's link storage, which locks
     * the connection and raises its links version as every link made does,
     * committed on another connection to the test's database, made the default
     * (and so SSO's storage connection) while it runs.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  ?string  $subject
     * @return void
     *
     * @throws \Throwable
     */
    private function linkElsewhere(#[\SensitiveParameter] VerifiedResult $result, Person $person, ?string $subject = null): void
    {
        $elsewhere = 'elsewhere';
        $default   = DB::getDefaultConnection();

        Config::set('database.connections.' . $elsewhere, Config::get('database.connections.' . self::CONNECTION));

        DB::setDefaultConnection($elsewhere);

        try {
            $storage    = $this->app?->make(LinkStorage::class) ?? self::fail('The application has not booted.');
            $linked     = $subject === null ? LinkSubject::of($result) : new LinkSubject($result->issuer, $subject);
            $connection = Connection::query()->findOrFail($result->connectionId);
            $created    = $storage->create($connection, $linked, (new IdentityReferences)->reference($person), LinkOrigin::LINK_PURPOSE, self::ssoClient());

            self::assertTrue($created->isCreated(), 'The other request\'s link was not made.');
        } finally {
            DB::setDefaultConnection($default);
            DB::purge($elsewhere);
        }
    }

    /**
     * Give the person a link by a verified domain in the connection given, on
     * the test's connection, inside whatever transaction is open there.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  string  $connectionId
     * @return void
     */
    private static function linkByDomain(Person $person, string $connectionId): void
    {
        $now     = CarbonImmutable::now()->utc()->format('Y-m-d H:i:s');
        $subject = new LinkSubject('https://domain.example.test', 'domain-subject-' . $person->id);

        DB::table('sso_links')->insert([
            'id'            => strtolower((string) Str::ulid()),
            'connection_id' => $connectionId,
            'issuer'        => $subject->issuer,
            'subject'       => $subject->subject,
            'subject_key'   => $subject->key(),
            'identity_type' => $person->getMorphClass(),
            'identity_id'   => (string) $person->id,
            'state'         => LinkState::ACTIVE->value,
            'provenance'    => LinkOrigin::VERIFIED_DOMAIN->value,
            'created_at'    => $now,
            'updated_at'    => $now,
        ]);
    }

    /**
     * Redeem the handoff code the redirect carries, for the flow's verifier,
     * and answer the sign-in.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\HandoffRedirect  $redirect
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    private function signInWith(HandoffRedirect $redirect): SignInResult
    {
        $verifier = $this->verifier ?? self::fail('No flow was started.');
        $answer   = Iam::signIns()->redeem(self::GUARD, $this->connectionId, $redirect->code(), $verifier, new SignInContext(self::client()));

        self::assertInstanceOf(SignInResult::class, $answer);
        self::assertTrue($answer->isSignedIn());

        return $answer;
    }

    /**
     * Assert the sign-in wrote a session, and that it is the person's.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInResult  $signedIn
     * @return void
     */
    private static function assertSessionOf(Person $person, SignInResult $signedIn): void
    {
        $session = $signedIn->session ?? self::fail('The sign-in wrote no session.');

        self::assertTrue($person->sessions()->whereKey($session->record->getKey())->exists(), 'The session is the person\'s.');
    }

    /**
     * Start a `sign_in` flow, have the provider answer it and complete it,
     * answering where the client is sent back to, with a code or a failure.
     *
     * @return \SineMacula\Laravel\Sso\Testing\HandoffRedirect
     *
     * @throws \Random\RandomException
     */
    private function complete(): HandoffRedirect
    {
        $app      = $this->app      ?? self::fail('The application has not booted.');
        $provider = $this->provider ?? self::fail('SSO is not arranged.');
        $start    = $this->started(Purpose::SIGN_IN, $this->connectionId, null, null);
        $request  = new CompletionRequest('GET', $provider->authorize($start)->query(), []);

        $this->verifier = $start->verifier?->reveal();

        $result = $app->make(CompletionService::class)->complete(CompletionEndpoint::CALLBACK, $this->connectionId, $request, self::ssoClient());

        return HandoffRedirect::from($app->make(CompletionResponses::class)->from($result, 'GET'));
    }

    /**
     * The one person provisioned.
     *
     * @return \Tests\Fixtures\Models\Person
     */
    private function onlyProvisioned(): Person
    {
        return Person::query()->sole();
    }

    /**
     * What SSO reported of the class given, in order.
     *
     * @template T of object
     *
     * @param  class-string<T>  $class
     * @return list<T>
     */
    private function reportedOf(string $class): array
    {
        return array_values(array_filter($this->reported->getArrayCopy(), static fn (object $event): bool => $event instanceof $class));
    }

    /**
     * Whether the exception, or any before it, carries the message.
     *
     * @param  \Throwable  $thrown
     * @param  string  $message
     * @return bool
     */
    private static function isOrFollows(\Throwable $thrown, string $message): bool
    {
        for ($link = $thrown; $link !== null; $link = $link->getPrevious()) {

            if (str_contains($link->getMessage(), $message)) {
                return true;
            }
        }

        return false;
    }

    /**
     * What the closure throws, failing the test unless it throws.
     *
     * @param  \Closure(): mixed  $call
     * @return \Throwable
     */
    private static function thrownBy(\Closure $call): \Throwable
    {
        try {
            $call();
        } catch (\Throwable $exception) {
            return $exception;
        }

        self::fail('Nothing was thrown.');
    }
}
