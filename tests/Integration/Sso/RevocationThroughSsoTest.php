<?php

declare(strict_types = 1);

namespace Tests\Integration\Sso;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Sso\SessionRevocationAdapter;
use SineMacula\Laravel\Sso\Connections\ConnectionLifecycle;
use SineMacula\Laravel\Sso\Connections\ConnectionResult;
use SineMacula\Laravel\Sso\Links\LinkService;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Link;
use Tests\Concerns\MigratesSso;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInPeople;
use Tests\Concerns\SignsInThroughLinks;
use Tests\TestCase;

/**
 * Integration tests for SSO's own changes ending `laravel-authentication`'s
 * sessions through this package's session revocation (IAM-4.4), inside the
 * transaction SSO makes each change in: disabling and deleting a connection end
 * the sessions established through it, unless `laravel-authentication`'s switch
 * for that is off, which leaves the change made; removing a link ends exactly
 * its sessions; and a revocation that throws, for an identity that no longer
 * resolves, rolls SSO's change back with it, on SQLite, and on MySQL and
 * PostgreSQL at READ COMMITTED and REPEATABLE READ.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionRevocationAdapter::class)]
final class RevocationThroughSsoTest extends TestCase
{
    use MigratesSso, RunsAtIsolationLevels, RunsSsoFlows, SignsInPeople, SignsInThroughLinks {
        SignsInThroughLinks::keyOf insteadof RunsSsoFlows;
        SignsInThroughLinks::referenceOf insteadof RunsSsoFlows;
        SignsInThroughLinks::signInMethods insteadof RunsSsoFlows;
    }

    /**
     * Rows of `[operation, switch]`: each change to a connection that ends its
     * sessions, with `laravel-authentication`'s switch for it.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideConnectionChanges(): iterable
    {
        yield 'disabled' => ['disable', 'authentication.revocation.connection_disabled'];

        yield 'deleted' => ['delete', 'authentication.revocation.connection_deleted'];
    }

    /**
     * Disabling or deleting a connection through SSO ends every session
     * established through it, in the change's own transaction, while
     * `laravel-authentication`'s switch for it is on, as it ships, and leaves
     * the sessions of the tenant's other connection standing.
     *
     * @param  string  $operation
     * @param  string  $switch
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideConnectionChanges')]
    public function testAConnectionsChangeEndsItsSessions(string $operation, string $switch): void
    {
        $this->arrangeSso();

        self::assertTrue(Config::get($switch));

        $other   = $this->makeConnection();
        $person  = $this->createPerson();
        $revoked = $this->signInThrough($person, $this->connectionId);
        $kept    = $this->signInThrough($person, $other);

        self::assertTrue($this->changeConnection($operation)->isSucceeded());

        self::assertNotNull($this->stored($revoked)->getRevokedAt());
        self::assertNull($this->stored($kept)->getRevokedAt());
    }

    /**
     * With `laravel-authentication`'s switch for the change off, the connection
     * is still disabled or deleted, and its sessions stand.
     *
     * @param  string  $operation
     * @param  string  $switch
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideConnectionChanges')]
    public function testAConnectionsChangeFollowsAuthenticationsSwitch(string $operation, string $switch): void
    {
        $this->arrangeSso();

        Config::set($switch, false);

        $session = $this->signInThrough($this->createPerson(), $this->connectionId);

        self::assertTrue($this->changeConnection($operation)->isSucceeded());
        self::assertFalse(Connection::query()->whereKey($this->connectionId)->where('enabled', true)->exists());
        self::assertNull($this->stored($session)->getRevokedAt());
    }

    /**
     * Removing a link through SSO ends exactly the sessions established through
     * it, in the removal's transaction, at either isolation level.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testRemovingALinkEndsExactlyItsSessions(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        $this->arrangeSso();

        $person  = $this->createPerson();
        $linkId  = (string) $this->linkThroughFlow($person)->linkId;
        $revoked = $this->signInThrough($person, $this->connectionId, $linkId);
        $kept    = $this->signInThrough($person, $this->connectionId, 'another-link');

        self::assertTrue($this->app?->make(LinkService::class)->remove(self::referenceOf($person), $linkId, self::ssoClient())->isRemoved());

        self::assertNotNull($this->stored($revoked)->getRevokedAt());
        self::assertNull($this->stored($kept)->getRevokedAt());
        self::assertFalse(Link::query()->whereKey($linkId)->exists());
    }

    /**
     * A link whose identity no longer resolves cannot have its sessions
     * revoked, so removing it throws, and SSO's removal rolls back: the link is
     * kept rather than removed with sessions nobody judged (IAM-8.2).
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARevocationThatThrowsRollsSsosChangeBack(): void
    {
        $this->arrangeSso();

        $person    = $this->createPerson();
        $reference = self::referenceOf($person);
        $linkId    = (string) $this->linkThroughFlow($person)->linkId;

        $person->newQuery()->whereKey($person->getKey())->delete();

        try {
            $this->app?->make(LinkService::class)->remove($reference, $linkId, self::ssoClient());

            self::fail('A link of an unresolved identity was removed.');
        } catch (UnresolvedReferenceException) {
            self::assertTrue(Link::query()->whereKey($linkId)->exists());
            self::assertSame(0, DB::connection()->transactionLevel());
        }
    }

    /**
     * Disable or delete the arranged connection through SSO.
     *
     * @param  string  $operation
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionResult
     *
     * @throws \Throwable
     */
    private function changeConnection(string $operation): ConnectionResult
    {
        $lifecycle = $this->app?->make(ConnectionLifecycle::class);

        self::assertInstanceOf(ConnectionLifecycle::class, $lifecycle);

        return $operation === 'disable'
            ? $lifecycle->disable(self::TENANT, $this->connectionId, self::ssoClient())
            : $lifecycle->delete(self::TENANT, $this->connectionId, self::ssoClient());
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
