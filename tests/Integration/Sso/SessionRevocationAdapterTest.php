<?php

declare(strict_types = 1);

namespace Tests\Integration\Sso;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Database\StorageConnection;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Tenancy\TenantRequirement;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Sso\SessionRevocationAdapter;
use SineMacula\Laravel\Iam\Testing\FakeTenantTree;
use SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Revocation\Enums\RevocationReason;
use SineMacula\Laravel\Sso\Revocation\Enums\RevocationScopeKind;
use SineMacula\Laravel\Sso\Revocation\RevocationScope;
use Tests\Concerns\MigratesMembers;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Concerns\SignsInThroughLinks;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Resolvers\ClaimedTenant;
use Tests\Fixtures\Resolvers\OpenTenancy;
use Tests\TestCase;

/**
 * Integration tests for SSO's session revocation through
 * `laravel-authentication` (IAM-4.4): each of SSO's four scopes ends exactly
 * the sessions it names, on every guard, through the one helper of
 * `laravel-authentication`'s for it; the connection and removed-link scopes
 * follow `laravel-authentication`'s own switches, while an enforcement change
 * and a widened scope are never skipped and a widened scope revoked twice
 * revokes nothing the second time; an enforcement change judges the sessions of
 * the enforcing tenant, and of every tenant below it in the application's
 * tenant tree, once more when the caller's transaction on the storage
 * connection commits, once every callback queued on it has run, whatever
 * another connection's transaction does, and, when another commit callback
 * fails, as the unit of work ends; and a tenant or identity that cannot be
 * resolved, or a scope missing what its kind names, throws inside the caller's
 * transaction, so the change rolls back (IAM-8.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionRevocationAdapter::class)]
final class SessionRevocationAdapterTest extends TestCase
{
    use MigratesMembers, RunsAtIsolationLevels, SignsInPeople, SignsInThroughLinks;

    /** @var string A second guard holding sessions of the same people. */
    private const string ADMIN = 'admin';

    /** @var string A connection of the same tenant whose sessions no scope here names. */
    private const string OTHER_CONNECTION = 'connection-2';

    /** @var string Another database connection, with transactions of its own. */
    private const string OTHER_DATABASE = 'other';

    /** @var string Another link of the same person's through the same connection. */
    private const string OTHER_LINK = 'link-2';

    /** @var string The enforcing tenant's parent in the tree. */
    private const string PARENT = 'tenant-1-parent';

    /** @var string The enforcing tenant's child in the tree. */
    private const string CHILD = 'tenant-1-child';

    /** @var string The child's own child. */
    private const string GRANDCHILD = 'tenant-1-grandchild';

    /**
     * Rows of `[reason, switch]`: each reason a connection's sessions are
     * revoked for, with `laravel-authentication`'s switch for it.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Revocation\Enums\RevocationReason, 1: string}>
     */
    public static function provideConnectionReasons(): iterable
    {
        yield 'disabled' => [RevocationReason::CONNECTION_DISABLED, 'authentication.revocation.connection_disabled'];

        yield 'deleted' => [RevocationReason::CONNECTION_DELETED, 'authentication.revocation.connection_deleted'];
    }

    /**
     * A connection disabled or deleted ends every session established through
     * it, of every person and on every guard, inside the caller's transaction,
     * and leaves every other session standing, while `laravel-authentication`'s
     * switch for the reason is on, as it ships.
     *
     * @param  \SineMacula\Laravel\Sso\Revocation\Enums\RevocationReason  $reason
     * @param  string  $switch
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideConnectionReasons')]
    public function testAConnectionsSessionsAreRevoked(RevocationReason $reason, string $switch): void
    {
        self::assertTrue(Config::get($switch));

        [$ada, $grace] = [$this->createPerson(), $this->createPerson()];

        $revoked = [$this->signInThrough($ada), $this->signInThrough($grace, guard: self::ADMIN)];
        $kept    = [$this->signInThrough($ada, self::OTHER_CONNECTION), $this->signIn($ada)->record];

        $this->revokeInTransaction(RevocationScope::connection(self::SSO_TENANT, self::SSO_CONNECTION, $reason));

        $this->assertRevoked($revoked);
        $this->assertStanding($kept);
    }

    /**
     * A connection's revocation follows `laravel-authentication`'s switch for
     * its reason: turned off, nothing is revoked, and nothing throws.
     *
     * @param  \SineMacula\Laravel\Sso\Revocation\Enums\RevocationReason  $reason
     * @param  string  $switch
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideConnectionReasons')]
    public function testAConnectionsRevocationFollowsAuthenticationsSwitch(RevocationReason $reason, string $switch): void
    {
        Config::set($switch, false);

        $session = $this->signInThrough($this->createPerson());

        $this->revokeInTransaction(RevocationScope::connection(self::SSO_TENANT, self::SSO_CONNECTION, $reason));

        $this->assertStanding([$session]);
    }

    /**
     * A removed link ends exactly the identity's sessions established through
     * that link, on every guard: its other links' sessions, its password
     * sessions and another person's through a link of the same id stand.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARemovedLinksSessionsAreRevoked(): void
    {
        [$ada, $grace] = [$this->createPerson(), $this->createPerson()];

        $revoked = [$this->signInThrough($ada), $this->signInThrough($ada, guard: self::ADMIN)];
        $kept    = [$this->signInThrough($ada, linkId: self::OTHER_LINK), $this->signIn($ada)->record, $this->signInThrough($grace)];

        $this->revokeInTransaction(RevocationScope::identityInConnection(self::SSO_TENANT, self::SSO_CONNECTION, self::referenceOf($ada), self::LINK));

        $this->assertRevoked($revoked);
        $this->assertStanding($kept);
    }

    /**
     * A removed link's revocation follows `laravel-authentication`'s switch:
     * turned off, nothing is revoked, and nothing throws.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARemovedLinksRevocationFollowsAuthenticationsSwitch(): void
    {
        Config::set('authentication.revocation.link_removed', false);

        $ada     = $this->createPerson();
        $session = $this->signInThrough($ada);

        $this->revokeInTransaction(RevocationScope::identityInConnection(self::SSO_TENANT, self::SSO_CONNECTION, self::referenceOf($ada), self::LINK));

        $this->assertStanding([$session]);
    }

    /**
     * A widened scope ends exactly the identity's sessions through the link,
     * whatever `laravel-authentication`'s switch for a removed link says, since
     * it is never mapped to that switchable revocation.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAWidenedScopesSessionsAreRevokedWhateverTheSwitchSays(): void
    {
        Config::set('authentication.revocation.link_removed', false);

        $ada     = $this->createPerson();
        $revoked = [$this->signInThrough($ada), $this->signInThrough($ada, guard: self::ADMIN)];
        $kept    = [$this->signInThrough($ada, linkId: self::OTHER_LINK), $this->signIn($ada)->record];

        $this->revokeInTransaction(RevocationScope::identityLink(self::SSO_TENANT, self::SSO_CONNECTION, self::referenceOf($ada), self::LINK));

        $this->assertRevoked($revoked);
        $this->assertStanding($kept);
    }

    /**
     * A widened scope revoked twice, as SSO may report one widening from the
     * principal's change and again from a resolution that finds it first,
     * revokes nothing and reports nothing the second time, and throws nothing:
     * a minute later, the session keeps the time it was first revoked at, and
     * no second revocation is announced.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAWidenedScopeRevokedTwiceRevokesNothingTheSecondTime(): void
    {
        $ada     = $this->createPerson();
        $session = $this->signInThrough($ada);
        $scope   = RevocationScope::identityLink(self::SSO_TENANT, self::SSO_CONNECTION, self::referenceOf($ada), self::LINK);

        $announced = new \ArrayObject;

        Event::listen(SessionRevoked::class, static function (SessionRevoked $event) use ($announced): void {
            $announced->append($event);
        });

        $this->revokeInTransaction($scope);

        $first      = $this->stored($session)->getRevokedAt();
        $firstCount = $announced->count();

        $this->travel(1)->minutes();

        $this->revokeInTransaction($scope);

        self::assertNotNull($first);
        self::assertSame(1, $firstCount);
        self::assertEquals($first, $this->stored($session)->getRevokedAt());
        self::assertCount($firstCount, $announced, 'The second revocation announced a session revoked again.');
    }

    /**
     * An enforcement change ends the sessions acting in the enforcing tenant
     * that the tenant authentication policy, as it now answers, no longer
     * allows, on every guard: the sessions through a connection it no longer
     * names are revoked, and those through one it names, or acting in another
     * tenant, stand.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testAnEnforcementChangeRevokesTheSessionsThePolicyNoLongerAllows(string $level): void
    {
        self::requireIsolationLevels();
        self::useIsolationLevel($level);

        $this->bindTenancy();

        [$ada, $grace] = [$this->createPerson(), $this->createPerson()];

        $revoked = [$this->inTenant($this->signInThrough($ada), self::SSO_TENANT), $this->inTenant($this->signInThrough($grace, guard: self::ADMIN), self::SSO_TENANT)];
        $kept    = [$this->inTenant($this->signInThrough($ada, self::OTHER_CONNECTION), self::SSO_TENANT), $this->inTenant($this->signInThrough($grace), 'tenant-2')];

        $this->revokeInTransaction(RevocationScope::tenant(EnforcementPolicy::required(self::SSO_TENANT, self::SSO_TENANT, [self::OTHER_CONNECTION], '7')));

        $this->assertRevoked($revoked);
        $this->assertStanding($kept);
    }

    /**
     * With the application's tenant tree, an enforcement change ends the
     * sessions the policy no longer allows in the enforcing tenant and in every
     * tenant below it, at any depth, and leaves every tenant's outside the
     * subtree standing; without one, only the enforcing tenant's.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAnEnforcementChangeRevokesThroughTheEnforcingTenantsSubtree(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $this->bindTenancy();

        [$ada, $grace] = [$this->createPerson(), $this->createPerson()];

        $below   = [$this->inTenant($this->signInThrough($ada), self::CHILD), $this->inTenant($this->signInThrough($grace, guard: self::ADMIN), self::GRANDCHILD)];
        $outside = [$this->inTenant($this->signInThrough($ada), self::PARENT), $this->inTenant($this->signInThrough($grace), 'tenant-2')];
        $scope   = RevocationScope::tenant(EnforcementPolicy::required(self::SSO_TENANT, self::SSO_TENANT, [self::OTHER_CONNECTION], '7'));

        $this->revokeInTransaction($scope);

        $this->assertStanding([...$below, ...$outside]);

        FakeTenantTree::fake($this->app)->place(self::PARENT)->place(self::SSO_TENANT, self::PARENT)->place(self::CHILD, self::SSO_TENANT)->place(self::GRANDCHILD, self::CHILD);

        $this->revokeInTransaction($scope);

        $this->assertRevoked($below);
        $this->assertStanding($outside);
    }

    /**
     * The second pass judges the whole subtree once the caller's transaction
     * commits, so a session that entered a tenant below the enforcing one once
     * the first pass had run is revoked then.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheSecondPassJudgesTheSubtreeOnceItCommits(): void
    {
        $this->bindTenancy();

        FakeTenantTree::fake($this->app)->place(self::SSO_TENANT)->place(self::CHILD, self::SSO_TENANT);

        $late = $this->signInThrough($this->createPerson());

        DB::connection(StorageConnection::name())->transaction(function () use ($late): void {

            $this->adapter()->revoke(RevocationScope::tenant(EnforcementPolicy::required(self::SSO_TENANT, self::SSO_TENANT, [self::OTHER_CONNECTION], '7')));

            $this->inTenant($late, self::CHILD);

            $this->assertStanding([$late]);
        });

        $this->assertRevoked([$late]);
    }

    /**
     * A tenant below the enforcing one that `laravel-authentication`'s tenant
     * resolver cannot resolve throws inside the caller's transaction before any
     * tenant is judged, so SSO's change rolls back and every session stands.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnresolvableTenantBelowTheEnforcingOneRollsTheChangeBack(): void
    {
        $this->bindTenancy();

        FakeTenantTree::fake($this->app)->place(self::SSO_TENANT)->place(self::CHILD, self::SSO_TENANT)->place(self::GRANDCHILD, self::CHILD);

        $session  = $this->inTenant($this->signInThrough($this->createPerson()), self::SSO_TENANT);
        $resolver = \Mockery::mock(TenantResolver::class);

        $resolver->allows('resolve')->andReturnUsing(static fn (string $tenantId): ?ClaimedTenant => $tenantId === self::GRANDCHILD ? null : new ClaimedTenant($tenantId));

        $this->app?->instance(TenantResolver::class, $resolver);

        try {
            $this->revokeInTransaction(RevocationScope::tenant(EnforcementPolicy::required(self::SSO_TENANT, self::SSO_TENANT, [self::OTHER_CONNECTION], '7')));

            self::fail('An unresolvable tenant below the enforcing one was judged around.');
        } catch (UnresolvedReferenceException $exception) {
            self::assertSame(ReferenceKind::TENANT, $exception->kind);
        }

        $this->assertStanding([$session]);
    }

    /**
     * An enforcement change judges the enforcing tenant's sessions once more
     * when the caller's transaction commits, so a session that entered the
     * tenant once the first pass had run, which no first pass saw, is revoked
     * then, and not before.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnEnforcementChangeJudgesTheTenantAgainOnceItCommits(): void
    {
        $this->bindTenancy();

        $late = $this->signInThrough($this->createPerson());

        DB::connection(StorageConnection::name())->transaction(function () use ($late): void {

            $this->adapter()->revoke(RevocationScope::tenant(EnforcementPolicy::required(self::SSO_TENANT, self::SSO_TENANT, [self::OTHER_CONNECTION], '7')));

            $this->inTenant($late, self::SSO_TENANT);

            $this->assertStanding([$late]);
        });

        $this->assertRevoked([$late]);
    }

    /**
     * The second pass runs only once every callback queued on the caller's
     * transaction has run, one queued after the revocation included, as SSO
     * queues its report of the change: a session that entered the tenant once
     * the first pass had run still stands when that callback runs, and is
     * revoked once the commit has finished.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheSecondPassRunsOnceEveryCallbackOfTheCommitHasRun(): void
    {
        $this->bindTenancy();

        $late       = $this->signInThrough($this->createPerson());
        $connection = DB::connection(StorageConnection::name());
        /** @var \ArrayObject<int, bool> $standing */
        $standing = new \ArrayObject;

        $connection->transaction(function () use ($late, $connection, $standing): void {

            $this->adapter()->revoke(RevocationScope::tenant(EnforcementPolicy::required(self::SSO_TENANT, self::SSO_TENANT, [self::OTHER_CONNECTION], '7')));

            $this->inTenant($late, self::SSO_TENANT);

            $connection->afterCommit(function () use ($late, $standing): void {
                $standing->append($this->stored($late)->getRevokedAt() === null);
            });
        });

        self::assertSame([true], $standing->getArrayCopy(), 'The second pass ran before a callback queued after it.');
        $this->assertRevoked([$late]);
    }

    /**
     * The second pass waits for the caller's transaction on the storage
     * connection alone: a transaction open on another connection when the
     * change is made, and rolled back before the change commits, does not take
     * the second pass with it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheSecondPassWaitsForTheStorageConnectionAlone(): void
    {
        Config::set('database.connections.' . self::OTHER_DATABASE, ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);

        $this->bindTenancy();

        $late  = $this->signInThrough($this->createPerson());
        $other = DB::connection(self::OTHER_DATABASE);

        DB::connection(StorageConnection::name())->transaction(function () use ($late, $other): void {

            $other->beginTransaction();

            $this->adapter()->revoke(RevocationScope::tenant(EnforcementPolicy::required(self::SSO_TENANT, self::SSO_TENANT, [self::OTHER_CONNECTION], '7')));

            $other->rollBack();

            $this->inTenant($late, self::SSO_TENANT);
        });

        $this->assertRevoked([$late]);
    }

    /**
     * Rows of `[before]`: whether the commit callback that fails is queued
     * before the revocation, as the first pass's reports and an earlier change
     * of the caller's are, or after it, as SSO's report of the change and a
     * listener of it are.
     *
     * @return iterable<string, array{0: bool}>
     */
    public static function provideFailingCallbacks(): iterable
    {
        yield 'a callback queued before the revocation' => [true];

        yield 'a callback queued after the revocation' => [false];
    }

    /**
     * A commit callback of the caller's transaction that fails, before the
     * revocation or after it, stops Laravel running the rest and firing the
     * commit event, so the change commits with the second pass still held: the
     * failure propagates, and a session that entered the tenant once the first
     * pass had run still stands until the unit of work ends, and is revoked
     * then.
     *
     * @param  bool  $before
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideFailingCallbacks')]
    public function testTheSecondPassStillRunsWhenAnotherCommitCallbackFails(bool $before): void
    {
        $this->bindTenancy();

        $late       = $this->signInThrough($this->createPerson());
        $connection = DB::connection(StorageConnection::name());
        $failure    = new \RuntimeException('A listener of the change failed.');

        try {
            $connection->transaction(function () use ($late, $connection, $failure, $before): void {

                if ($before) {
                    $connection->afterCommit(static fn () => throw $failure);
                }

                $this->adapter()->revoke(RevocationScope::tenant(EnforcementPolicy::required(self::SSO_TENANT, self::SSO_TENANT, [self::OTHER_CONNECTION], '7')));

                $this->inTenant($late, self::SSO_TENANT);

                if ($before) {
                    return;
                }

                $connection->afterCommit(static fn () => throw $failure);
            });

            self::fail('The callback\'s failure did not propagate.');
        } catch (\RuntimeException $exception) {
            self::assertSame($failure, $exception);
        }

        $this->assertStanding([$late]);

        $this->app?->terminate();

        $this->assertRevoked([$late]);
    }

    /**
     * A tenant `laravel-authentication`'s tenant resolver cannot resolve, as
     * its default resolves none, throws inside the caller's transaction, so the
     * enforcement change rolls back with everything it wrote and no session is
     * left unjudged (IAM-8.2).
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnresolvedTenantThrowsAndTheChangeRollsBack(): void
    {
        $ada     = $this->createPerson();
        $session = $this->inTenant($this->signInThrough($ada), self::SSO_TENANT);

        try {
            DB::connection(StorageConnection::name())->transaction(function () use ($ada): void {

                $ada->forceFill(['name' => 'Changed in the transaction'])->save();

                $this->adapter()->revoke(RevocationScope::tenant(EnforcementPolicy::required(self::SSO_TENANT, self::SSO_TENANT, [self::OTHER_CONNECTION], '7')));
            });

            self::fail('An unresolved tenant was revoked for.');
        } catch (UnresolvedReferenceException $exception) {
            self::assertSame(ReferenceKind::TENANT, $exception->kind);
        }

        self::assertSame('Ada Lovelace', $ada->refresh()->getAttribute('name'));
        $this->assertStanding([$session]);
    }

    /**
     * A tenant resolver that answers a tenant of another identifier would have
     * another tenant's sessions judged, so the tenant is unresolved too.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantResolvedUnderAnotherIdentifierThrows(): void
    {
        $resolver = \Mockery::mock(TenantResolver::class);

        $resolver->allows('resolve')->andReturn(new ClaimedTenant('tenant-2'));

        $this->app?->instance(TenantResolver::class, $resolver);

        $this->expectException(UnresolvedReferenceException::class);

        $this->revokeInTransaction(RevocationScope::tenant(EnforcementPolicy::required(self::SSO_TENANT, self::SSO_TENANT, [self::OTHER_CONNECTION], '7')));
    }

    /**
     * An identity scope naming an identity that cannot be resolved throws, the
     * removed link's and the widened scope's alike, and nothing is revoked
     * (IAM-8.2).
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnresolvedIdentityThrows(): void
    {
        $session  = $this->signInThrough($this->createPerson());
        $stranger = new IdentityReference(Person::class, '987654');

        foreach ([RevocationScope::identityInConnection(...), RevocationScope::identityLink(...)] as $scope) {
            try {
                $this->revokeInTransaction($scope(self::SSO_TENANT, self::SSO_CONNECTION, $stranger, self::LINK));

                self::fail('An unresolved identity was revoked for.');
            } catch (UnresolvedReferenceException $exception) {
                self::assertSame(ReferenceKind::IDENTITY, $exception->kind);
            }
        }

        $this->assertStanding([$session]);
    }

    /**
     * Rows of `[kind, reason, part]`: a scope of each kind missing a part its
     * kind names, as SSO's named constructors never build one, and the part.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Revocation\Enums\RevocationScopeKind, 1: \SineMacula\Laravel\Sso\Revocation\Enums\RevocationReason, 2: string}>
     */
    public static function provideIncompleteScopes(): iterable
    {
        yield 'a connection scope with no connection' => [RevocationScopeKind::CONNECTION, RevocationReason::CONNECTION_DISABLED, 'connection'];

        yield 'a connection scope for another reason' => [RevocationScopeKind::CONNECTION, RevocationReason::LINK_REMOVED, 'reason'];

        yield 'a removed link with no identity' => [RevocationScopeKind::IDENTITY_CONNECTION, RevocationReason::LINK_REMOVED, 'identity'];

        yield 'a removed link with no connection' => [RevocationScopeKind::IDENTITY_CONNECTION, RevocationReason::LINK_REMOVED, 'connection'];

        yield 'a removed link with no link' => [RevocationScopeKind::IDENTITY_CONNECTION, RevocationReason::LINK_REMOVED, 'link'];

        yield 'a widened scope with no identity' => [RevocationScopeKind::IDENTITY_LINK, RevocationReason::SCOPE_WIDENED, 'identity'];

        yield 'a widened scope with no connection' => [RevocationScopeKind::IDENTITY_LINK, RevocationReason::SCOPE_WIDENED, 'connection'];

        yield 'a widened scope with no link' => [RevocationScopeKind::IDENTITY_LINK, RevocationReason::SCOPE_WIDENED, 'link'];
    }

    /**
     * A scope missing what its kind names is a `LogicException`, and nothing is
     * revoked: what it meant to end cannot be told.
     *
     * @param  \SineMacula\Laravel\Sso\Revocation\Enums\RevocationScopeKind  $kind
     * @param  \SineMacula\Laravel\Sso\Revocation\Enums\RevocationReason  $reason
     * @param  string  $part
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIncompleteScopes')]
    public function testAnIncompleteScopeIsRefused(RevocationScopeKind $kind, RevocationReason $reason, string $part): void
    {
        $ada     = $this->createPerson();
        $session = $this->signInThrough($ada);
        $scope   = self::scope($kind, $reason, [
            'connectionId' => $part === 'connection' ? null : self::SSO_CONNECTION,
            'identity'     => $part === 'identity' ? null : self::referenceOf($ada),
            'linkId'       => $part === 'link' ? null : self::LINK,
        ]);

        try {
            $this->revokeInTransaction($scope);

            self::fail('An incomplete scope was revoked for.');
        } catch (\LogicException $exception) {
            self::assertStringContainsString($part === 'reason' ? '[link_removed]' : 'names its ' . $part, $exception->getMessage());
        }

        $this->assertStanding([$session]);
    }

    /**
     * A revocation made inside the caller's transaction rolls back with it: the
     * sessions it ended stand again once the caller's change fails.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARevocationRollsBackWithTheCallersChange(): void
    {
        $session = $this->signInThrough($this->createPerson());

        try {
            DB::connection(StorageConnection::name())->transaction(function () use ($session): void {

                $this->adapter()->revoke(RevocationScope::connection(self::SSO_TENANT, self::SSO_CONNECTION, RevocationReason::CONNECTION_DISABLED));

                $this->assertRevoked([$session]);

                throw new \RuntimeException('The change failed.');
            });
        } catch (\RuntimeException) {
            // The caller's change failed after the revocation.
        }

        $this->assertStanding([$session]);
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
     * The adapter, as the container builds it.
     *
     * @return \SineMacula\Laravel\Iam\Sso\SessionRevocationAdapter
     */
    private function adapter(): SessionRevocationAdapter
    {
        $adapter = $this->app?->make(SessionRevocationAdapter::class);

        self::assertInstanceOf(SessionRevocationAdapter::class, $adapter);

        return $adapter;
    }

    /**
     * Revoke the scope inside a transaction on the storage connection, as SSO
     * calls the contract inside the change it makes.
     *
     * @param  \SineMacula\Laravel\Sso\Revocation\RevocationScope  $scope
     * @return void
     *
     * @throws \Throwable
     */
    private function revokeInTransaction(RevocationScope $scope): void
    {
        DB::connection(StorageConnection::name())->transaction(fn () => $this->adapter()->revoke($scope));
    }

    /**
     * Bind a tenancy in which every tenant resolves, and a tenant
     * authentication policy that requires a session to come through the other
     * connection alone.
     *
     * @return void
     */
    private function bindTenancy(): void
    {
        $policy = \Mockery::mock(TenantAuthenticationPolicy::class);

        $policy->allows('requirementFor')->andReturn(new TenantRequirement('7', connections: [self::OTHER_CONNECTION]));

        $this->app?->instance(TenantResolver::class, new OpenTenancy);
        $this->app?->instance(TenantAuthenticationPolicy::class, $policy);
    }

    /**
     * The session, made to act in the tenant.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  string  $tenantId
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession
     */
    private function inTenant(EloquentSession&Model $session, string $tenantId): EloquentSession&Model
    {
        $session->newQuery()->whereKey($session->getKey())->update([$session->getTenantIdName() => $tenantId]);

        return $session;
    }

    /**
     * Assert each session is revoked, as stored now.
     *
     * @param  list<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession>  $sessions
     * @return void
     */
    private function assertRevoked(array $sessions): void
    {
        foreach ($sessions as $session) {
            self::assertNotNull($this->stored($session)->getRevokedAt(), self::keyOf($session));
        }
    }

    /**
     * Assert each session stands, unrevoked, as stored now.
     *
     * @param  list<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession>  $sessions
     * @return void
     */
    private function assertStanding(array $sessions): void
    {
        foreach ($sessions as $session) {
            self::assertNull($this->stored($session)->getRevokedAt(), self::keyOf($session));
        }
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

    /**
     * A scope of the kind and reason with the parts given, built past SSO's
     * named constructors, which never build an incomplete one.
     *
     * @param  \SineMacula\Laravel\Sso\Revocation\Enums\RevocationScopeKind  $kind
     * @param  \SineMacula\Laravel\Sso\Revocation\Enums\RevocationReason  $reason
     * @param  array{connectionId: ?string, identity: ?\SineMacula\Laravel\Sso\Identities\IdentityReference, linkId: ?string}  $parts
     * @return \SineMacula\Laravel\Sso\Revocation\RevocationScope
     */
    private static function scope(RevocationScopeKind $kind, RevocationReason $reason, array $parts): RevocationScope
    {
        $class = new \ReflectionClass(RevocationScope::class);
        $scope = $class->newInstanceWithoutConstructor();

        $class->getConstructor()?->invoke($scope, $kind, $reason, self::SSO_TENANT, $parts['connectionId'], $parts['identity'], null, $parts['linkId']);

        return $scope;
    }
}
