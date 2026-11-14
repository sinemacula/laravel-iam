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
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Database\StorageConnection;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Tenancy\TenantRequirement;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Iam\Exceptions\Enums\ReferenceKind;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Sso\IdentityReferences;
use SineMacula\Laravel\Iam\Sso\SessionRevocationAdapter;
use SineMacula\Laravel\Sso\Contracts\EnforcementExemption;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy;
use SineMacula\Laravel\Sso\Enforcement\EnforcementService;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Revocation\Enums\RevocationReason;
use SineMacula\Laravel\Sso\Revocation\Enums\RevocationScopeKind;
use SineMacula\Laravel\Sso\Revocation\RevocationScope;
use SineMacula\Laravel\Sso\Testing\Seams\Concerns\SessionRevocationContract;
use Tests\Concerns\MigratesSso;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInPeople;
use Tests\Concerns\SignsInThroughLinks;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Resolvers\ClaimedTenant;
use Tests\Fixtures\Resolvers\OpenTenancy;
use Tests\Fixtures\Tenancy\ExemptsIdentities;
use Tests\Fixtures\Tenancy\StoredTenantTree;
use Tests\TestCase;

/**
 * Integration tests for SSO's session revocation adapter.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionRevocationAdapter::class)]
final class SessionRevocationAdapterTest extends TestCase
{
    use MigratesSso, RunsAtIsolationLevels, RunsSsoFlows, SessionRevocationContract, SignsInPeople, SignsInThroughLinks {
        SignsInThroughLinks::keyOf insteadof RunsSsoFlows;
        SignsInThroughLinks::referenceOf insteadof RunsSsoFlows;
        SignsInThroughLinks::signInMethods insteadof RunsSsoFlows;
    }

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

    /** @var string A tenant apart from the enforcing one's tree. */
    private const string APART = 'tenant-2';

    /** @var ?array{0: string, 1: string} The connection the enforcing tenant's rule allows, and another, once stored. */
    private ?array $ruled = null;

    /** @var list<\Tests\Fixtures\Models\Person> A person and an exempt one, once created. */
    private array $people = [];

    /**
     * Rows of `[reason, switch]`: each connection reason and its switch.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Revocation\Enums\RevocationReason, 1: string}>
     */
    public static function provideConnectionReasons(): iterable
    {
        yield 'disabled' => [RevocationReason::CONNECTION_DISABLED, 'authentication.revocation.connection_disabled'];

        yield 'deleted' => [RevocationReason::CONNECTION_DELETED, 'authentication.revocation.connection_deleted'];
    }

    /**
     * A disabled or deleted connection ends exactly its sessions.
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
     * A connection's revocation follows authentication's switch.
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
     * A removed link ends exactly its identity's sessions through it.
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
     * A removed link's revocation follows authentication's switch.
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
     * A widened scope ends its sessions whatever the switch says.
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
     * A widened scope revoked twice revokes nothing the second time.
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
     * An enforcement change revokes the sessions the policy no longer allows.
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
     * An enforcement change judges the whole subtree when there is a tree.
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

        $this->placeChain(self::PARENT, self::SSO_TENANT, self::CHILD, self::GRANDCHILD);

        $this->revokeInTransaction($scope);

        $this->assertRevoked($below);
        $this->assertStanding($outside);
    }

    /**
     * The second pass judges the subtree once the change commits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheSecondPassJudgesTheSubtreeOnceItCommits(): void
    {
        $this->bindTenancy();

        $this->placeChain(self::SSO_TENANT, self::CHILD);

        $late = $this->signInThrough($this->createPerson());

        DB::connection(StorageConnection::name())->transaction(function () use ($late): void {

            $this->adapter()->revoke(RevocationScope::tenant(EnforcementPolicy::required(self::SSO_TENANT, self::SSO_TENANT, [self::OTHER_CONNECTION], '7')));

            $this->inTenant($late, self::CHILD);

            $this->assertStanding([$late]);
        });

        $this->assertRevoked([$late]);
    }

    /**
     * An unresolvable tenant below the enforcing one rolls the change back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnresolvableTenantBelowTheEnforcingOneRollsTheChangeBack(): void
    {
        $this->bindTenancy();

        $this->placeChain(self::SSO_TENANT, self::CHILD, self::GRANDCHILD);

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
     * An enforcement change judges the tenant again once it commits.
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
     * The second pass waits for the storage connection alone.
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
     * The second pass runs before a later commit callback fails.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheSecondPassRunsBeforeALaterCommitCallbackFails(): void
    {
        $this->bindTenancy();

        $late       = $this->signInThrough($this->createPerson());
        $connection = DB::connection(StorageConnection::name());
        $failure    = new \RuntimeException('A listener of the change failed.');

        try {
            $connection->transaction(function () use ($late, $connection, $failure): void {

                $this->adapter()->revoke(RevocationScope::tenant(EnforcementPolicy::required(self::SSO_TENANT, self::SSO_TENANT, [self::OTHER_CONNECTION], '7')));

                $this->inTenant($late, self::SSO_TENANT);

                $connection->afterCommit(static fn () => throw $failure);
            });

            self::fail('The callback\'s failure did not propagate.');
        } catch (\RuntimeException $exception) {
            self::assertSame($failure, $exception);
        }

        $this->assertRevoked([$late]);
    }

    /**
     * The second pass still runs when an earlier commit callback fails.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheSecondPassStillRunsWhenAnEarlierCommitCallbackFails(): void
    {
        $this->bindTenancy();

        $late       = $this->signInThrough($this->createPerson());
        $connection = DB::connection(StorageConnection::name());
        $failure    = new \RuntimeException('An earlier change of the caller\'s failed.');

        try {
            $connection->transaction(function () use ($late, $connection, $failure): void {

                $connection->afterCommit(static fn () => throw $failure);

                $this->adapter()->revoke(RevocationScope::tenant(EnforcementPolicy::required(self::SSO_TENANT, self::SSO_TENANT, [self::OTHER_CONNECTION], '7')));

                $this->inTenant($late, self::SSO_TENANT);
            });

            self::fail('The callback\'s failure did not propagate.');
        } catch (\RuntimeException $exception) {
            self::assertSame($failure, $exception);
        }

        $this->app?->terminate();

        $this->assertRevoked([$late]);
    }

    /**
     * An unresolved tenant throws and the change rolls back.
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
     * A tenant resolved under another identifier throws.
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
     * An unresolved identity throws and nothing is revoked.
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
     * Rows of `[kind, reason, part]`: each scope missing a part.
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
     * A scope missing what its kind names is a `LogicException`.
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
     * The adapter under SSO's session revocation contract kit.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\SessionRevocation
     */
    #[\Override]
    protected function sessionRevocation(): SessionRevocation
    {
        return $this->adapter();
    }

    /**
     * The enforcing tenant, one apart from it and its child.
     *
     * @return array{0: string, 1: string, 2: string}
     */
    #[\Override]
    protected function revocationTenants(): array
    {
        return [self::SSO_TENANT, self::APART, self::CHILD];
    }

    /**
     * The enforcing tenant's connections, its rule stored once.
     *
     * @return array{0: string, 1: string}
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function revocationConnections(): array
    {
        return $this->ruled ??= $this->storeTheRule();
    }

    /**
     * A person, and another the application exempts.
     *
     * @return array{0: \SineMacula\Laravel\Sso\Identities\IdentityReference, 1: \SineMacula\Laravel\Sso\Identities\IdentityReference}
     */
    #[\Override]
    protected function revocationIdentities(): array
    {
        if ($this->people === []) {
            $this->people = [$this->createPerson(), $this->createPerson()];

            $this->app?->instance(EnforcementExemption::class, (new ExemptsIdentities)->exempt(self::referenceOf($this->people[1])));
        }

        return [self::referenceOf($this->people[0]), self::referenceOf($this->people[1])];
    }

    /**
     * Sign the person in through the connection, or with a password, and move
     * the session into the tenant.
     *
     * @param  string  $tenantId
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $connectionId
     * @return array{0: string, 1: ?string}
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function startRevocableSession(string $tenantId, IdentityReference $identity, ?string $connectionId): array
    {
        $person = (new IdentityReferences)->identity($identity);

        self::assertInstanceOf(Person::class, $person);

        if ($connectionId === null) {
            return [self::keyOf($this->inTenant($this->signIn($person)->record, $tenantId)), null];
        }

        $linkId = 'link-' . self::keyOf($person) . '-' . $connectionId;

        return [self::keyOf($this->inTenant($this->signInThrough($person, $connectionId, $linkId), $tenantId)), $linkId];
    }

    /**
     * Whether the session is unrevoked, as stored now.
     *
     * @param  string  $sessionId
     * @return bool
     */
    #[\Override]
    protected function isSessionActive(string $sessionId): bool
    {
        return Session::query()->findOrFail($sessionId)->getRevokedAt() === null;
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
     * Revoke the scope inside a transaction on the storage connection.
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
     * Bind the application's tree, each tenant placed below the one before it.
     *
     * @param  string  ...$tenantIds
     * @return void
     */
    private function placeChain(string ...$tenantIds): void
    {
        $parent = null;

        foreach ($tenantIds as $tenantId) {
            StoredTenantTree::place($tenantId, $parent);

            $parent = $tenantId;
        }

        $this->app?->instance(TenantTree::class, new StoredTenantTree);
    }

    /**
     * Store the enforcing tenant's rule through SSO, allowing its first
     * connection, with the child below it; the connections.
     *
     * @return array{0: string, 1: string}
     *
     * @throws \Throwable
     */
    private function storeTheRule(): array
    {
        $this->arrangeSso();

        Config::set('sso.features.enforcement', true);

        $this->app?->instance(TenantResolver::class, new OpenTenancy);
        $this->app?->instance(TenantAccess::class, new OpenTenancy);

        $this->placeChain(self::SSO_TENANT, self::CHILD);

        $connections = [$this->connectionId, $this->makeConnection()];

        DB::table('sso_connections')->where('id', $connections[0])->update(['has_completed_sign_in' => true]);

        $service = $this->app?->make(EnforcementService::class) ?? self::fail('The application has not booted.');
        $result  = $service->update(self::SSO_TENANT, true, [$connections[0]], self::ssoClient());

        self::assertTrue($result->isChanged(), sprintf('The rule was not stored: [%s].', $result->reason->value ?? $result->status->value));

        return $connections;
    }

    /**
     * Bind a tenancy whose policy requires the other connection.
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
     * A scope built past SSO's named constructors, which never omit a part.
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
