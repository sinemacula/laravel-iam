<?php

declare(strict_types = 1);

namespace Tests\Integration\Sso;

use Illuminate\Auth\GenericUser;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\DeadlockException;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Sso\LinkRedemption;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\SingleUseStore;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\FlowFailed;
use SineMacula\Laravel\Sso\Events\HandoffRedeemed;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Freshness\RefusingFreshness;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkService;
use SineMacula\Laravel\Sso\Links\LinkSummary;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\SingleUse\DatabaseSingleUseStore;
use Tests\Concerns\MigratesSso;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Sso\FailingFreshness;
use Tests\Fixtures\Sso\FailingSingleUseStore;
use Tests\Fixtures\Sso\Handoff;
use Tests\Fixtures\Transactions\SavepointLeavingConnections;
use Tests\TestCase;

/**
 * Integration tests for redeeming a `link` handoff code SSO issued through its
 * standalone redemption, as the caller the application hands over (IAM-4.3):
 * the caller is linked, no session is written and nothing is admitted; a code
 * started for another identity links nobody; a caller that cannot be named to
 * SSO throws before the code is touched; until freshness is bound, SSO's
 * default refuses every link; a concurrency failure is redeemed again,
 * standalone, until the attempts run out, but never once the attempt reached
 * its commit, and inside the caller's transaction reaches the caller once, as
 * its retry recognises it, with none of SSO's writes left in that transaction.
 *
 * Each scenario that commits or rolls back runs at the connection's own level
 * on every engine, then at READ COMMITTED and REPEATABLE READ on MySQL and
 * PostgreSQL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LinkRedemption::class)]
final class LinkRedemptionTest extends TestCase
{
    use MigratesSso, RunsAtIsolationLevels, RunsSsoFlows, SignsInPeople;

    /** @var string The message PostgreSQL fails a transaction that cannot be serialised with. */
    private const string SERIALISATION_FAILURE = 'SQLSTATE[40001]: Serialization failure: 7 ERROR:  could not serialize access due to concurrent update';

    /** @var string The message MySQL fails a statement that waited too long for a lock with. */
    private const string LOCK_WAIT_TIMEOUT = 'SQLSTATE[HY000]: General error: 1205 Lock wait timeout exceeded; try restarting transaction';

    /** @var \ArrayObject<int, object> What SSO reported of each redemption, in order. */
    private \ArrayObject $reported;

    /**
     * Arrange SSO, and listen for what each redemption reports.
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

        Event::listen([FlowFailed::class, HandoffRedeemed::class], static function (object $event) use ($reported): void {
            $reported->append($event);
        });
    }

    /**
     * The caller is linked to the provider's subject, standalone: the
     * redemption commits before it answers, is redeemed but not admitted, and
     * writes no session; one `HandoffRedeemed` reports it, carrying the client
     * handed over.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testTheCallerIsLinkedStandalone(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person  = $this->createPerson();
        $handoff = $this->handoff(Purpose::LINK, $person);
        $linked  = Iam::links()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, self::client(), $person);
        $links   = $this->app?->make(LinkService::class)->list(self::referenceOf($person)) ?? [];

        self::assertTrue($linked->isRedeemed());
        self::assertFalse($linked->isAdmitted());
        self::assertTrue($linked->linkedIdentity?->is(self::referenceOf($person)));
        self::assertSame([$linked->linkId], array_map(static fn (LinkSummary $link): string => $link->id, $links));
        self::assertSame(LinkState::ACTIVE, $links[0]->state);
        self::assertSame(0, DB::connection()->transactionLevel());
        self::assertSame(0, DB::table('authentication_sessions')->count());
        self::assertSame([HandoffRedeemed::class], $this->reportedEvents());

        $event = $this->reported[0];

        self::assertInstanceOf(HandoffRedeemed::class, $event);
        self::assertSame([self::CLIENT_IP, self::CLIENT_AGENT], [$event->context->ip, $event->context->userAgent]);
    }

    /**
     * A code started for another identity is refused as `identity_mismatch`,
     * and links neither of them.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testACodeStartedForAnotherIdentityLinksNobody(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person   = $this->createPerson();
        $stranger = $this->createPerson();
        $handoff  = $this->handoff(Purpose::LINK, $person);
        $refused  = Iam::links()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, self::client(), $stranger);
        $service  = $this->app?->make(LinkService::class) ?? self::fail('The application has not booted.');

        self::assertTrue($refused->isRefused());
        self::assertSame(FailureReason::IDENTITY_MISMATCH, $refused->reason);
        self::assertSame([], $service->list(self::referenceOf($person)));
        self::assertSame([], $service->list(self::referenceOf($stranger)));
        self::assertSame([FlowFailed::class], $this->reportedEvents());
    }

    /**
     * A caller that is no Eloquent identity cannot be named to SSO, and throws
     * before the code is touched, so the code still links the person it was
     * started for.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACallerThatCannotBeNamedThrowsBeforeTheCodeIsTouched(): void
    {
        $person  = $this->createPerson();
        $handoff = $this->handoff(Purpose::LINK, $person);
        $caller  = new class (['id' => $person->getKey()]) extends GenericUser implements Identity {};

        try {
            Iam::links()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, self::client(), $caller);

            self::fail('A caller that cannot be named was linked.');
        } catch (UnresolvedReferenceException $exception) {
            self::assertSame(ReferenceKind::IDENTITY, $exception->kind);
        }

        self::assertSame([], $this->reportedEvents());
        self::assertTrue(Iam::links()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, self::client(), $person)->isRedeemed());
    }

    /**
     * An application that is no guard of the `jwt` driver throws before SSO is
     * asked, so the code is not spent and still links the person it was started
     * for through the application it was started for.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnApplicationThatIsNoSessionGuardThrowsBeforeTheCodeIsTouched(): void
    {
        $person  = $this->createPerson();
        $handoff = $this->handoff(Purpose::LINK, $person);

        try {
            Iam::links()->redeem('web', $this->connectionId, $handoff->code, $handoff->verifier, self::client(), $person);

            self::fail('A link was redeemed for an application that is no session guard.');
        } catch (UnresolvedReferenceException $exception) {
            self::assertSame(ReferenceKind::GUARD, $exception->kind);
        }

        self::assertSame([], $this->reportedEvents());
        self::assertSame([], $this->app?->make(LinkService::class)->list(self::referenceOf($person)));
        self::assertTrue(Iam::links()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, self::client(), $person)->isRedeemed());
    }

    /**
     * A job's redemption, with a client of which nothing is known, reports
     * neither an IP address nor a user agent.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAJobsRedemptionReportsNoClient(): void
    {
        $person  = $this->createPerson();
        $handoff = $this->handoff(Purpose::LINK, $person);

        self::assertTrue(Iam::links()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, new ClientContext(null, null), $person)->isRedeemed());

        $event = $this->reported[0];

        self::assertInstanceOf(HandoffRedeemed::class, $event);
        self::assertSame([null, null], [$event->context->ip, $event->context->userAgent]);
    }

    /**
     * SSO's default freshness, which this package replaces with
     * `laravel-authentication`'s (IAM-4.6) and an application may bind again,
     * refuses every link as not fresh, and the code is spent.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSsosDefaultFreshnessRefusesEveryLink(): void
    {
        $person  = $this->createPerson();
        $handoff = $this->handoff(Purpose::LINK, $person);

        $this->app?->instance(Freshness::class, new RefusingFreshness);

        $refused = Iam::links()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, self::client(), $person);

        self::assertTrue($refused->isRefused());
        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $refused->reason);
        self::assertSame([], $this->app?->make(LinkService::class)->list(self::referenceOf($person)));
    }

    /**
     * A standalone redemption whose transaction fails to serialise, rolled back
     * whole by SSO, is redeemed again from its start, still standalone, and
     * links the caller once, reported once.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAConcurrencyFailureIsRedeemedAgainStandalone(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person  = $this->createPerson();
        $handoff = $this->handoff(Purpose::LINK, $person);
        $store   = $this->failingStore(self::serialisationFailure(...), 1);
        $linked  = $this->redeem($handoff, $person);

        self::assertTrue($linked->isRedeemed());
        self::assertFalse($linked->isAdmitted());
        self::assertSame(2, $store->calls);
        self::assertCount(1, $this->app?->make(LinkService::class)->list(self::referenceOf($person)) ?? []);
        self::assertSame([HandoffRedeemed::class], $this->reportedEvents());
    }

    /**
     * The last attempt's concurrency failure reaches the caller as it was
     * thrown, after as many attempts as the retry helper is configured with,
     * and leaves the code unspent and nothing reported, so the request retried
     * links the caller.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheLastAttemptsFailureReachesTheCaller(): void
    {
        Config::set('iam.transactions.attempts', 2);

        $person  = $this->createPerson();
        $handoff = $this->handoff(Purpose::LINK, $person);
        $store   = $this->failingStore(self::serialisationFailure(...), 2);

        try {
            $this->redeem($handoff, $person);

            self::fail('A redemption that failed on every attempt answered.');
        } catch (QueryException $exception) {
            self::assertSame('40001', $exception->getCode());
        }

        self::assertSame(2, $store->calls);
        self::assertSame([], $this->reportedEvents());
        self::assertTrue($this->redeem($handoff, $person)->isRedeemed());
    }

    /**
     * The last attempt's concurrency failure, met in a transaction SSO nests in
     * its own and so wrapped in Laravel's `DeadlockException`, which loses its
     * SQLSTATE, reaches the caller as the database raised it, a
     * `QueryException` with SQLSTATE 40001, and leaves the code unspent.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheLastAttemptsFailureInANestedTransactionReachesTheCallerAsTheDatabaseRaisedIt(): void
    {
        Config::set('iam.transactions.attempts', 2);

        $person  = $this->createPerson();
        $handoff = $this->handoff(Purpose::LINK, $person);
        $raised  = self::serialisationFailure();
        $store   = $this->failingStore(static fn (): \Throwable => new DeadlockException($raised->getMessage(), 0, $raised), 2);

        try {
            $this->redeem($handoff, $person);

            self::fail('A redemption that failed on every attempt answered.');
        } catch (QueryException $exception) {
            self::assertSame($raised, $exception);
        }

        self::assertSame(2, $store->calls);
        self::assertSame([], $this->reportedEvents());
        self::assertTrue($this->redeem($handoff, $person)->isRedeemed());
    }

    /**
     * A failure that is no concurrency failure reaches the caller from the
     * first attempt, which is not run again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailureThatIsNoConcurrencyFailureIsNotRetried(): void
    {
        $person  = $this->createPerson();
        $handoff = $this->handoff(Purpose::LINK, $person);
        $store   = $this->failingStore(static fn (): \Throwable => new \RuntimeException('The store is unavailable.'), 1);

        try {
            $this->redeem($handoff, $person);

            self::fail('A redemption whose store failed answered.');
        } catch (\RuntimeException $exception) {
            self::assertSame('The store is unavailable.', $exception->getMessage());
        }

        self::assertSame(1, $store->calls);
    }

    /**
     * A concurrency failure met once the standalone attempt has committed, as
     * from a listener of an event SSO dispatches from its commit, reaches the
     * caller as it was thrown and is not redeemed again: the link is made once,
     * the code is spent, and no refusal of it is reported.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAFailureOnceTheAttemptHasCommittedIsNotRedeemedAgain(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person  = $this->createPerson();
        $handoff = $this->handoff(Purpose::LINK, $person);
        $thrown  = new \ArrayObject;

        Event::listen(HandoffRedeemed::class, static function () use ($thrown): void {

            if ($thrown->count() > 0) {
                return;
            }

            $thrown->append(true);

            throw self::serialisationFailure();
        });

        try {
            $this->redeem($handoff, $person);

            self::fail('A failure once the attempt had committed was swallowed.');
        } catch (QueryException $exception) {
            self::assertSame('40001', $exception->getCode());
        }

        self::assertSame(0, DB::connection()->transactionLevel());
        self::assertCount(1, $this->app?->make(LinkService::class)->list(self::referenceOf($person)) ?? []);
        self::assertSame(1, HandoffCode::query()->whereNotNull('redeemed_at')->count());
        self::assertSame([HandoffRedeemed::class], $this->reportedEvents());
    }

    /**
     * Rows of `[whether the connection leaves the savepoint]`: the installed
     * Laravel, and Laravel before 13.40, which only lowers the transaction
     * level after a concurrency failure in a nested transaction.
     *
     * @return iterable<string, array{0: bool}>
     */
    public static function provideSavepointHandling(): iterable
    {
        yield 'as the installed Laravel handles it' => [false];

        yield 'as Laravel before 13.40 handles it' => [true];
    }

    /**
     * Inside the caller's transaction, a concurrency failure the database met
     * on one statement alone, after SSO consumed the code (as freshness is
     * asked), undoes everything SSO wrote, on every supported Laravel version:
     * a caller that catches the failure and commits leaves the code unspent, so
     * it still links the caller.
     *
     * @param  bool  $leavesTheSavepoint
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideSavepointHandling')]
    public function testInsideTheCallersTransactionAConcurrencyFailureLeavesTheCodeUnspent(bool $leavesTheSavepoint): void
    {
        $person  = $this->createPerson();
        $handoff = $this->handoff(Purpose::LINK, $person);

        if ($leavesTheSavepoint) {
            SavepointLeavingConnections::replace($this->app?->make(DatabaseManager::class) ?? self::fail('The application has not booted.'), self::CONNECTION);
        }

        $app       = $this->app ?? self::fail('The application has not booted.');
        $freshness = new FailingFreshness($app->make(Freshness::class), static fn (): \Throwable => new \RuntimeException(self::LOCK_WAIT_TIMEOUT), 1);
        $thrown    = null;

        $app->instance(Freshness::class, $freshness);

        DB::beginTransaction();

        try {
            $this->redeem($handoff, $person);
        } catch (DeadlockException $thrown) {
            // Asserted below, beside what the caller's transaction kept.
        }

        self::assertInstanceOf(DeadlockException::class, $thrown);
        self::assertSame(1, DB::transactionLevel());

        DB::commit();

        self::assertSame(1, $freshness->calls);
        self::assertSame(0, HandoffCode::query()->whereNotNull('redeemed_at')->count());
        self::assertSame([], $this->reportedEvents());
        self::assertTrue($this->redeem($handoff, $person)->isRedeemed());
    }

    /**
     * Inside the caller's transaction, the link is admitted, written in that
     * transaction and committed with it.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testInsideTheCallersTransactionTheLinkCommitsWithIt(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person  = $this->createPerson();
        $handoff = $this->handoff(Purpose::LINK, $person);
        $linked  = DB::transaction(fn (): mixed => $this->redeem($handoff, $person));

        self::assertInstanceOf(RedemptionResult::class, $linked);
        self::assertTrue($linked->isRedeemed());
        self::assertTrue($linked->isAdmitted());
        self::assertCount(1, $this->app?->make(LinkService::class)->list(self::referenceOf($person)) ?? []);
    }

    /**
     * Inside the caller's transaction, a failure to serialise is not retried:
     * it reaches the caller once, as the failure itself rather than Laravel's
     * wrapper of it that its detector cannot recognise, so the caller's own
     * retry retries its whole transaction.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testInsideTheCallersTransactionAFailureReachesTheCallerAsItsRetryRecognisesIt(): void
    {
        $person  = $this->createPerson();
        $handoff = $this->handoff(Purpose::LINK, $person);
        $store   = $this->failingStore(self::serialisationFailure(...), 1);

        try {
            DB::transaction(fn (): mixed => $this->redeem($handoff, $person));

            self::fail('A redemption that failed to serialise answered.');
        } catch (\Throwable $exception) {
            self::assertNotInstanceOf(DeadlockException::class, $exception);
            self::assertInstanceOf(QueryException::class, $exception);
            self::assertSame('40001', $exception->getCode());
        }

        self::assertSame(1, $store->calls);
        self::assertSame([], $this->app?->make(LinkService::class)->list(self::referenceOf($person)));
    }

    /**
     * Redeem the `link` handoff for the guard through the connection, for the
     * tests' client, as the person.
     *
     * @param  \Tests\Fixtures\Sso\Handoff  $handoff
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     *
     * @throws \Throwable
     */
    private function redeem(Handoff $handoff, Person $person): RedemptionResult
    {
        return Iam::links()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, self::client(), $person);
    }

    /**
     * Bind SSO's single-use store to one failing its first records with the
     * failure given, and answer it.
     *
     * @param  \Closure(): \Throwable  $failure
     * @param  int  $failures
     * @return \Tests\Fixtures\Sso\FailingSingleUseStore
     */
    private function failingStore(\Closure $failure, int $failures): FailingSingleUseStore
    {
        $app   = $this->app ?? self::fail('The application has not booted.');
        $store = new FailingSingleUseStore($app->make(DatabaseSingleUseStore::class), $failure, $failures);

        $app->instance(SingleUseStore::class, $store);

        return $store;
    }

    /**
     * PostgreSQL's failure to serialise, as the query that met it throws it.
     *
     * @return \Illuminate\Database\QueryException
     */
    private static function serialisationFailure(): QueryException
    {
        $failure = new \PDOException(self::SERIALISATION_FAILURE);

        (new \ReflectionProperty(\Exception::class, 'code'))->setValue($failure, '40001');

        $failure->errorInfo = ['40001', 7, self::SERIALISATION_FAILURE];

        return new QueryException(self::CONNECTION, 'insert into "sso_single_use" ("key") values (?)', ['key'], $failure);
    }

    /**
     * The class of each event reported, in order.
     *
     * @return list<class-string>
     */
    private function reportedEvents(): array
    {
        return array_values(array_map(static fn (object $event): string => $event::class, $this->reported->getArrayCopy()));
    }
}
