<?php

declare(strict_types = 1);

namespace Tests\Unit\Sso;

use Illuminate\Container\Container;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Iam\Sso\BoundLinkStorage;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\LinkStorage;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\LinkCreation;
use SineMacula\Laravel\Sso\Links\LinkReservations;
use SineMacula\Laravel\Sso\Links\LinkResolution;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Links\NoLinks;
use Tests\Fixtures\Sso\Redemptions;

/**
 * Unit tests for SSO's link storage as the bound linker is it: every call is
 * answered by the linker bound at that moment, with exactly what it was given,
 * and a linker that is no link storage, or that is this storage itself, is a
 * `LogicException` before anything is read or written.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(BoundLinkStorage::class)]
final class BoundLinkStorageTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var string The link every call names. */
    private const string LINK = 'link-1';

    /** @var \Illuminate\Container\Container The container the linker is bound in. */
    private Container $container;

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Sso\Contracts\LinkStorage The bound linker. */
    private LinkStorage $linker;

    /** @var \SineMacula\Laravel\Iam\Sso\BoundLinkStorage The storage under test. */
    private BoundLinkStorage $storage;

    /**
     * Bind a link storage as the linker.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->container = new Container;
        $this->linker    = \Mockery::mock(LinkStorage::class);
        $this->storage   = new BoundLinkStorage($this->container);

        $this->container->instance(Linker::class, $this->linker);
    }

    /**
     * A resolution is the bound linker's, for exactly the result and client.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAResolutionIsTheBoundLinkers(): void
    {
        $result     = Redemptions::verified();
        $client     = self::client();
        $resolution = LinkResolution::absent();

        $this->linker->expects('resolve')->with($result, $client)->andReturn($resolution);

        self::assertSame($resolution, $this->storage->resolve($result, $client));
    }

    /**
     * The holdings are the bound linker's count, for exactly the connection and
     * identity.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheHoldingsAreTheBoundLinkers(): void
    {
        $identity = Redemptions::identity();

        $this->linker->expects('holdings')->with(Redemptions::CONNECTION, $identity)->andReturn(2);

        self::assertSame(2, $this->storage->holdings(Redemptions::CONNECTION, $identity));
    }

    /**
     * A creation is made through the bound linker with every value given, the
     * optional ones included.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testACreationIsMadeThroughTheBoundLinker(): void
    {
        $connection = \Mockery::mock(SsoConnection::class);
        $subject    = LinkSubject::of(Redemptions::verified());
        $identity   = Redemptions::identity();
        $client     = self::client();
        $caller     = new Caller($identity, 'session-7');
        $reference  = RequestReference::fromString(Redemptions::REFERENCE);
        $creation   = LinkCreation::subjectAlreadyLinked();

        $this->linker->expects('create')
            ->with($connection, $subject, $identity, LinkOrigin::LINK_PURPOSE, $client, $caller, Redemptions::APPLICATION, Purpose::LINK, $reference)
            ->andReturn($creation);

        $created = $this->storage->create($connection, $subject, $identity, LinkOrigin::LINK_PURPOSE, $client, $caller, Redemptions::APPLICATION, Purpose::LINK, $reference);

        self::assertSame($creation, $created);
    }

    /**
     * A creation given only what it requires hands the bound linker nothing in
     * place of the rest.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testACreationWithItsDefaultsHandsOnNothingElse(): void
    {
        $connection = \Mockery::mock(SsoConnection::class);
        $subject    = LinkSubject::of(Redemptions::verified());
        $identity   = Redemptions::identity();
        $client     = self::client();
        $creation   = LinkCreation::linkLimitReached();

        $this->linker->expects('create')
            ->with($connection, $subject, $identity, LinkOrigin::PROVISIONING, $client, null, null, null, null)
            ->andReturn($creation);

        self::assertSame($creation, $this->storage->create($connection, $subject, $identity, LinkOrigin::PROVISIONING, $client));
    }

    /**
     * A confirmation is made through the bound linker with every value given,
     * and with nothing in place of what is left out.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAConfirmationIsMadeThroughTheBoundLinker(): void
    {
        $connection = \Mockery::mock(SsoConnection::class);
        $client     = self::client();
        $reference  = RequestReference::fromString(Redemptions::REFERENCE);

        $this->linker->expects('confirm')->with($connection, self::LINK, $client, Redemptions::APPLICATION, $reference);
        $this->linker->expects('confirm')->with($connection, self::LINK, $client, null, null);

        $this->storage->confirm($connection, self::LINK, $client, Redemptions::APPLICATION, $reference);
        $this->storage->confirm($connection, self::LINK, $client);
    }

    /**
     * A suspension is made through the bound linker with exactly what it was
     * given.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testASuspensionIsMadeThroughTheBoundLinker(): void
    {
        $identity = Redemptions::identity();
        $client   = self::client();

        $this->linker->expects('suspend')->with(self::LINK, $identity, Redemptions::CONNECTION, Redemptions::TENANT, 'oidc', $client);

        $this->storage->suspend(self::LINK, $identity, Redemptions::CONNECTION, Redemptions::TENANT, 'oidc', $client);
    }

    /**
     * The sessions through a link are revoked through the bound linker with
     * exactly what it was given.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheSessionsAreRevokedThroughTheBoundLinker(): void
    {
        $identity = Redemptions::identity();

        $this->linker->expects('revokeSessions')->with(self::LINK, $identity, Redemptions::CONNECTION, Redemptions::TENANT);

        $this->storage->revokeSessions(self::LINK, $identity, Redemptions::CONNECTION, Redemptions::TENANT);
    }

    /**
     * The reservations' writer is the bound linker's.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheReservationsAreTheBoundLinkers(): void
    {
        $reservations = new LinkReservations(\Mockery::mock(Clock::class), $this->container);

        $this->linker->expects('reservations')->andReturn($reservations);

        self::assertSame($reservations, $this->storage->reservations());
    }

    /**
     * The linker is resolved on each call, so one bound after the storage was
     * made answers.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheLinkerBoundAtTheCallAnswers(): void
    {
        $identity = Redemptions::identity();
        $later    = \Mockery::mock(LinkStorage::class);

        $this->linker->expects('holdings')->never();
        $later->expects('holdings')->with(Redemptions::CONNECTION, $identity)->andReturn(5);

        $this->container->instance(Linker::class, $later);

        self::assertSame(5, $this->storage->holdings(Redemptions::CONNECTION, $identity));
    }

    /**
     * Rows of `[linker]`: a linker that is no link storage of its own.
     *
     * @return iterable<string, array{0: \Closure(\Illuminate\Container\Container): \SineMacula\Laravel\Sso\Contracts\Linker}>
     */
    public static function provideLinkersThatAreNoStorage(): iterable
    {
        yield 'SSO\'s default, which links nothing' => [static fn (Container $container): Linker => new NoLinks];

        yield 'a linker that is no link storage' => [static fn (Container $container): Linker => \Mockery::mock(Linker::class)];

        yield 'this storage itself' => [static fn (Container $container): Linker => new BoundLinkStorage($container)];
    }

    /**
     * A linker that is no link storage of its own is a `LogicException` naming
     * it, before anything is read or written.
     *
     * @param  \Closure(\Illuminate\Container\Container): \SineMacula\Laravel\Sso\Contracts\Linker  $linker
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideLinkersThatAreNoStorage')]
    public function testALinkerThatIsNoStorageIsALogicException(\Closure $linker): void
    {
        $bound = $linker($this->container);

        $this->container->instance(Linker::class, $bound);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(sprintf(BoundLinkStorage::NOT_STORAGE, LinkStorage::class, Linker::class, $bound::class, LinkStore::class));

        $this->storage->holdings(Redemptions::CONNECTION, Redemptions::identity());
    }

    /**
     * The client every call is made for.
     *
     * @return \SineMacula\Laravel\Sso\Http\ClientContext
     */
    private static function client(): ClientContext
    {
        return new ClientContext('203.0.113.7', 'Agent/1.0');
    }
}
