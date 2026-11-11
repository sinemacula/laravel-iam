<?php

declare(strict_types = 1);

namespace Tests\Integration\Sso;

use Illuminate\Auth\GenericUser;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Callers\Caller;
use SineMacula\Laravel\Authentication\Callers\Enums\CallerCredential;
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
use SineMacula\Laravel\Sso\SingleUse\DatabaseSingleUseStore;
use Tests\Concerns\MigratesSso;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Sso\FailingSingleUseStore;
use Tests\Fixtures\Sso\Handoff;
use Tests\TestCase;

/**
 * Integration tests for redeeming a `link` handoff code SSO issued through its
 * standalone redemption, as the caller the application hands over (IAM-4.3):
 * the caller is linked, no session is written and nothing is admitted; a code
 * started for another identity links nobody; a caller that cannot be named to
 * SSO throws before the code is touched; until freshness is bound, SSO's
 * default refuses every link; and a concurrency failure is the caller's to
 * retry, inside its transaction or not.
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
        $linked  = Iam::links()->redeem($this->connectionId, $handoff->code, $handoff->verifier, self::client(), $this->requestCallerOf($person));
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
        $refused  = Iam::links()->redeem($this->connectionId, $handoff->code, $handoff->verifier, self::client(), $this->requestCallerOf($stranger));
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
            Iam::links()->redeem($this->connectionId, $handoff->code, $handoff->verifier, self::client(), $this->requestCallerOf($caller));

            self::fail('A caller that cannot be named was linked.');
        } catch (UnresolvedReferenceException $exception) {
            self::assertSame(ReferenceKind::IDENTITY, $exception->kind);
        }

        self::assertSame([], $this->reportedEvents());
        self::assertTrue(Iam::links()->redeem($this->connectionId, $handoff->code, $handoff->verifier, self::client(), $this->requestCallerOf($person))->isRedeemed());
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
            Iam::links()->redeem($this->connectionId, $handoff->code, $handoff->verifier, self::client(), new Caller('web', CallerCredential::ACCESS, $person, null, null, null));

            self::fail('A link was redeemed for an application that is no session guard.');
        } catch (UnresolvedReferenceException $exception) {
            self::assertSame(ReferenceKind::GUARD, $exception->kind);
        }

        self::assertSame([], $this->reportedEvents());
        self::assertSame([], $this->app?->make(LinkService::class)->list(self::referenceOf($person)));
        self::assertTrue(Iam::links()->redeem($this->connectionId, $handoff->code, $handoff->verifier, self::client(), $this->requestCallerOf($person))->isRedeemed());
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
        $caller  = $this->requestCallerOf($person);

        self::assertTrue(Iam::links()->redeem($this->connectionId, $handoff->code, $handoff->verifier, new ClientContext(null, null), $caller)->isRedeemed());

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

        $refused = Iam::links()->redeem($this->connectionId, $handoff->code, $handoff->verifier, self::client(), $this->requestCallerOf($person));

        self::assertTrue($refused->isRefused());
        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $refused->reason);
        self::assertSame([], $this->app?->make(LinkService::class)->list(self::referenceOf($person)));
    }

    /**
     * A standalone redemption's concurrency failure is not retried here: it
     * reaches the caller from the one attempt with the code unspent and nothing
     * reported, so the request retried links the caller.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStandaloneConcurrencyFailureReachesTheCaller(): void
    {
        $person  = $this->createPerson();
        $handoff = $this->handoff(Purpose::LINK, $person);
        $store   = $this->failingStore(self::serialisationFailure(...), 1);

        try {
            $this->redeem($handoff, $person);

            self::fail('A redemption that failed to serialise answered.');
        } catch (QueryException $exception) {
            self::assertSame('40001', $exception->getCode());
        }

        self::assertSame(1, $store->calls);
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
     * it reaches the caller from the one attempt, with nothing linked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testInsideTheCallersTransactionAFailureToSerialiseReachesTheCaller(): void
    {
        $person  = $this->createPerson();
        $handoff = $this->handoff(Purpose::LINK, $person);
        $store   = $this->failingStore(self::serialisationFailure(...), 1);

        try {
            DB::transaction(fn (): mixed => $this->redeem($handoff, $person));

            self::fail('A redemption that failed to serialise answered.');
        } catch (\Throwable $exception) {
            self::assertStringContainsString('could not serialize access', $exception->getMessage());
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
        return Iam::links()->redeem($this->connectionId, $handoff->code, $handoff->verifier, self::client(), $this->requestCallerOf($person));
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
