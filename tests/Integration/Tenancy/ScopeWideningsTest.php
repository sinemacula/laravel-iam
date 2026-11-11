<?php

declare(strict_types = 1);

namespace Tests\Integration\Tenancy;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Tenancy\ScopeWidenings;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Events\LinkSuspended;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Revocation\RevocationScope;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken;
use Tests\Concerns\MigratesSso;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInPeople;
use Tests\Concerns\SignsInThroughLinks;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Sso\PlainIdentity;
use Tests\TestCase;

/**
 * Integration tests for reporting that a person comes to hold a principal
 * (IAM-7.3), through SSO's scope widening, against the revocation checks of
 * SSO's guide to this package: inside the transaction that gives it, the
 * person's link by a verified domain in a connection of another tenant is
 * suspended and the sessions established through it are revoked in that
 * transaction, whatever any setting says, and a second report suspends and
 * revokes nothing more; several people reported together are each suspended; a
 * link in the new principal's own tenant is left alone, and a platform
 * principal reaches every tenant's; outside a transaction it is a
 * `LogicException` with nothing locked or written; a revocation that throws
 * rolls the report back, so a caller that catches it keeps no suspension; and
 * an identity that cannot be named throws before anything is touched. Every
 * suspension SSO reports carries the IP address and user agent of the client
 * the caller handed in, as SSO's guide's context check asks.
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
#[CoversClass(ScopeWidenings::class)]
final class ScopeWideningsTest extends TestCase
{
    use MigratesSso, RunsAtIsolationLevels, RunsSsoFlows, SignsInPeople, SignsInThroughLinks {
        SignsInThroughLinks::keyOf insteadof RunsSsoFlows;
        SignsInThroughLinks::referenceOf insteadof RunsSsoFlows;
        SignsInThroughLinks::signInMethods insteadof RunsSsoFlows;
    }

    /** @var string The tenant of the connection the person's link by a verified domain is in. */
    private const string OTHER_TENANT = 'tenant-2';

    /** @var ?\Tests\Fixtures\Models\Person The person whose principals change. */
    private ?Person $person = null;

    /** @var string The person's link by a verified domain, in the other tenant's connection. */
    private string $linkId = '';

    /** @var string The other tenant's connection. */
    private string $otherConnectionId = '';

    /** @var \ArrayObject<int, \SineMacula\Laravel\Sso\Events\LinkSuspended> Every suspension SSO reported, in order. */
    private \ArrayObject $suspended;

    /**
     * Arrange SSO, and give the person a link by a verified domain in a
     * connection of the other tenant, with a session established through it.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeSso();

        $this->person            = $this->createPerson();
        $this->otherConnectionId = $this->makeConnection(self::OTHER_TENANT);
        $tenantConnection        = $this->connectionId;
        $this->connectionId      = $this->otherConnectionId;
        $this->linkId            = (string) $this->linkThroughFlow($this->person)->linkId;
        $this->connectionId      = $tenantConnection;

        Link::query()->whereKey($this->linkId)->update(['provenance' => LinkOrigin::VERIFIED_DOMAIN->value]);

        $suspended       = new \ArrayObject;
        $this->suspended = $suspended;

        Event::listen(LinkSuspended::class, static function (LinkSuspended $event) use ($suspended): void {
            $suspended->append($event);
        });
    }

    /**
     * A membership of the tenant suspends the person's link by a verified
     * domain in the other tenant's connection and revokes the session
     * established through it, in the transaction that gives the membership,
     * and SSO reports the suspension for the client the caller handed in;
     * reported again, it suspends and revokes nothing more.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAPrincipalOfAnotherTenantSuspendsTheLinkAndRevokesItsSessions(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person  = $this->person();
        $session = $this->signInThrough($person, $this->otherConnectionId, $this->linkId);

        self::assertSame(1, Iam::transaction(fn (): int => Iam::scopeWidenings()->widen([$person], self::TENANT, self::client())));
        self::assertSame(LinkState::SUSPENDED, $this->link()->state);
        self::assertNotNull($this->stored($session)->getRevokedAt());
        $this->assertSuspendedFor(self::CLIENT_IP, self::CLIENT_AGENT);

        $revokedAt = $this->stored($session)->getRevokedAt();

        self::assertSame(0, Iam::transaction(fn (): int => Iam::scopeWidenings()->widen([$person], self::TENANT, self::client())));
        self::assertSame(LinkState::SUSPENDED, $this->link()->state);
        self::assertEquals($revokedAt, $this->stored($session)->getRevokedAt());
        self::assertCount(1, $this->suspended);
    }

    /**
     * Several people reported together each have their link by a verified
     * domain in the other tenant's connection suspended.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testSeveralPeopleReportedTogetherAreEachSuspended(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person = $this->person();
        $second = $this->createPerson();
        $linkId = $this->linkInOtherTenant($second);

        self::assertSame(2, Iam::transaction(fn (): int => Iam::scopeWidenings()->widen([$second, $person], self::TENANT, self::client())));
        self::assertSame(LinkState::SUSPENDED, $this->link()->state);
        self::assertSame(LinkState::SUSPENDED, Link::query()->findOrFail($linkId)->state);
    }

    /**
     * A platform principal, of no tenant, reaches beyond every tenant, so the
     * link in the other tenant's connection is suspended too, reported for the
     * client the caller handed in.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAPlatformPrincipalSuspendsTheLink(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person = $this->person();
        $client = new ClientContext('198.51.100.7', 'platform-console');

        self::assertSame(1, Iam::transaction(fn (): int => Iam::scopeWidenings()->widen([$person], null, $client)));
        self::assertSame(LinkState::SUSPENDED, $this->link()->state);
        $this->assertSuspendedFor('198.51.100.7', 'platform-console');
    }

    /**
     * A report for a client with no IP address or user agent, as a job's, is
     * reported so.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAClientWithNothingKnownIsReportedSo(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person = $this->person();

        self::assertSame(1, Iam::transaction(fn (): int => Iam::scopeWidenings()->widen([$person], self::TENANT, new ClientContext(null, null))));
        $this->assertSuspendedFor(null, null);
    }

    /**
     * A membership of the link's own tenant is inside it: the link is left
     * active, and its session standing.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAPrincipalOfTheLinksOwnTenantLeavesItAlone(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person  = $this->person();
        $session = $this->signInThrough($person, $this->otherConnectionId, $this->linkId);

        self::assertSame(0, Iam::transaction(fn (): int => Iam::scopeWidenings()->widen([$person], self::OTHER_TENANT, self::client())));
        self::assertSame(LinkState::ACTIVE, $this->link()->state);
        self::assertNull($this->stored($session)->getRevokedAt());
    }

    /**
     * Outside a transaction on the storage connection it is SSO's
     * `LogicException`, with nothing suspended or revoked and no transaction
     * left open.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOutsideATransactionItIsRefused(): void
    {
        $person  = $this->person();
        $session = $this->signInThrough($person, $this->otherConnectionId, $this->linkId);

        try {
            Iam::scopeWidenings()->widen([$person], self::TENANT, self::client());

            self::fail('A widened scope was reported outside a transaction.');
        } catch (\LogicException $exception) {
            self::assertStringContainsString('inside the transaction that changes the person\'s principals', $exception->getMessage());
        }

        self::assertSame(LinkState::ACTIVE, $this->link()->state);
        self::assertNull($this->stored($session)->getRevokedAt());
        self::assertSame(0, DB::connection()->transactionLevel());
    }

    /**
     * The report is the change's: rolled back with the caller's transaction,
     * the link is active again and its session standing.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testItRollsBackWithTheCallersTransaction(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person   = $this->person();
        $session  = $this->signInThrough($person, $this->otherConnectionId, $this->linkId);
        $rollback = new \RuntimeException('The membership could not be written.');

        try {
            Iam::transaction(function () use ($person, $rollback): never {
                Iam::scopeWidenings()->widen([$person], self::TENANT, self::client());

                throw $rollback;
            });
        } catch (\RuntimeException $exception) {
            self::assertSame($rollback, $exception);
        }

        self::assertSame(LinkState::ACTIVE, $this->link()->state);
        self::assertNull($this->stored($session)->getRevokedAt());
    }

    /**
     * A revocation that throws fails the report, in a savepoint of the caller's
     * transaction rolled back, so a caller that catches it and commits keeps no
     * suspension.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testARevocationThatThrowsLeavesNoSuspension(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $failure = new \RuntimeException('The sessions could not be revoked.');

        $this->app?->instance(SessionRevocation::class, new class ($failure) implements SessionRevocation {
            /**
             * Constructor.
             *
             * @param  \RuntimeException  $failure
             */
            public function __construct(

                /** What every revocation throws. */
                private readonly \RuntimeException $failure,
            ) {}

            /**
             * Throw.
             *
             * @param  \SineMacula\Laravel\Sso\Revocation\RevocationScope  $scope
             * @return void
             *
             * @throws \RuntimeException
             *
             * @SuppressWarnings("php:S1172")
             */
            #[\Override]
            public function revoke(RevocationScope $scope): void
            {
                throw $this->failure;
            }
        });

        $person = $this->person();
        $caught = Iam::transaction(static function () use ($person): ?\Throwable {
            try {
                Iam::scopeWidenings()->widen([$person], self::TENANT, self::client());
            } catch (\RuntimeException $exception) {
                return $exception;
            }

            return null;
        });

        self::assertSame($failure, $caught);
        self::assertSame(LinkState::ACTIVE, $this->link()->state);
        self::assertSame(0, DB::connection()->transactionLevel());
    }

    /**
     * An identity that is no Eloquent model cannot be named to SSO, and throws
     * before anything is locked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityThatCannotBeNamedThrows(): void
    {
        $this->expectException(UnresolvedReferenceException::class);

        Iam::transaction(static fn (): int => Iam::scopeWidenings()->widen([new PlainIdentity(['id' => 1])], self::TENANT, self::client()));
    }

    /**
     * Assert SSO reported one suspension, of the person's link by a verified
     * domain, for the client given.
     *
     * @param  ?string  $ip
     * @param  ?string  $userAgent
     * @return void
     */
    private function assertSuspendedFor(?string $ip, ?string $userAgent): void
    {
        self::assertCount(1, $this->suspended, 'SSO did not report the one suspension.');

        $context = ($this->suspended[0] ?? self::fail('No suspension was reported.'))->context;

        self::assertSame($this->otherConnectionId, $context->connectionId);
        self::assertSame($ip, $context->ip, 'The suspension was reported for another IP address than the caller\'s client.');
        self::assertSame($userAgent, $context->userAgent, 'The suspension was reported for another user agent than the caller\'s client.');
    }

    /**
     * Link the person by a verified domain in the other tenant's connection, to
     * a subject of their own; answer the link's id.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @return string
     *
     * @throws \Random\RandomException
     */
    private function linkInOtherTenant(Person $person): string
    {
        $tenantConnection   = $this->connectionId;
        $this->connectionId = $this->otherConnectionId;
        $handoff            = $this->handoff(Purpose::LINK, $person, tailor: static fn (FakeIdToken $token): FakeIdToken => $token->with('sub', 'second-subject'));
        $linked             = Iam::links()->redeem($this->otherConnectionId, $handoff->code, $handoff->verifier, self::client(), $this->requestCallerOf($person));
        $this->connectionId = $tenantConnection;

        self::assertTrue($linked->isRedeemed(), 'The second person was not linked.');

        Link::query()->whereKey($linked->linkId)->update(['provenance' => LinkOrigin::VERIFIED_DOMAIN->value]);

        return (string) $linked->linkId;
    }

    /**
     * The person whose principals change.
     *
     * @return \Tests\Fixtures\Models\Person
     */
    private function person(): Person
    {
        return $this->person ?? self::fail('No person is arranged.');
    }

    /**
     * The person's link by a verified domain, as stored now.
     *
     * @return \SineMacula\Laravel\Sso\Models\Link
     */
    private function link(): Link
    {
        return Link::query()->findOrFail($this->linkId);
    }

    /**
     * The session as it is stored now.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession
     */
    private function stored(EloquentSession&Model $session): EloquentSession&Model
    {
        $stored = $session->newQuery()->find($session->getKey());

        self::assertInstanceOf(EloquentSession::class, $stored);
        self::assertInstanceOf(Model::class, $stored);

        return $stored;
    }
}
