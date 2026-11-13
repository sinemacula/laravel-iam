<?php

declare(strict_types = 1);

namespace Tests\Integration\EndToEnd;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Events\TransactionBeginning;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Authorization\Exceptions\RoleExclusionConflictException;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\RoleExclusionService;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Iam\Contracts\GroupResync;
use SineMacula\Laravel\Iam\Contracts\Provisioner;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Provisioning\GrantInstruction;
use SineMacula\Laravel\Iam\Provisioning\GroupGrants;
use SineMacula\Laravel\Iam\Provisioning\GroupSettings;
use SineMacula\Laravel\Iam\Provisioning\MappedGroupResync;
use SineMacula\Laravel\Iam\Provisioning\ProvisionOnUnlinkedResult;
use SineMacula\Laravel\Iam\Sso\SignInRedemption;
use SineMacula\Laravel\Iam\Testing\FakeGroupMapping;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken;
use Tests\Concerns\MigratesAuthorization;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Authorization\Organisation;
use Tests\Fixtures\Authorization\OrganisationTenancy;
use Tests\Fixtures\Models\Person;
use Tests\Fixtures\Provisioning\ProvisionedMembership;
use Tests\Fixtures\Provisioning\ProvisionsPeople;
use Tests\Fixtures\Sso\Handoff;
use Tests\TestCase;

/**
 * End-to-end tests for a provider's groups mapped to grants (IAM-7.2), through
 * SSO's whole flow against a fake OpenID provider, provisioning and this
 * package's sign-in redemption: a first sign-in reporting groups is provisioned
 * a person granted, in the connection's tenant, the roles the mapping answers
 * for them, in the provisioning's one transaction; a mapping that refuses, or
 * names a role that does not exist, rolls the person, the membership and the
 * link back with it; with the application's opt-in, a later sign-in re-syncs
 * the person's roles in the tenant to the groups then reported, granting the
 * roles of a group added and revoking those of a group removed, never one the
 * mapping does not answer and never one of another tenant; a re-sync runs once
 * the sign-in has committed, never under SSO's redemption locks, so one that
 * refuses grants and revokes nothing and hands out no credential, the code
 * spent; and with no re-sync bound a later sign-in changes nothing.
 *
 * Each flow that commits runs at the connection's own level on every engine,
 * then at READ COMMITTED and REPEATABLE READ on MySQL and PostgreSQL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProvisionOnUnlinkedResult::class)]
#[CoversClass(SignInRedemption::class)]
#[CoversClass(GroupGrants::class)]
#[CoversClass(GroupSettings::class)]
#[CoversClass(MappedGroupResync::class)]
final class GroupGrantsThroughSsoTest extends TestCase
{
    use MigratesAuthorization, RunsAtIsolationLevels, RunsSsoFlows, SignsInPeople;

    /** @var string The role the finance group gives. */
    private const string VIEWER = 'invoices.viewer';

    /** @var string The role the finance operations group adds. */
    private const string APPROVER = 'invoices.approver';

    /** @var string A role no group gives. */
    private const string ADMIN = 'admin';

    /** @var ?\SineMacula\Laravel\Iam\Testing\FakeGroupMapping The application's group mapping. */
    private ?FakeGroupMapping $mapping = null;

    /**
     * Arrange SSO, store the roles, provision people, map the groups, and
     * resolve every tenant to the organisation of its id.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeSso();

        foreach ([self::VIEWER, self::APPROVER, self::ADMIN] as $role) {
            Role::query()->create(['name' => $role]);
        }

        $this->app?->instance(ProvisionsPeople::class, new ProvisionsPeople);
        $this->app?->instance(TenantResolver::class, new OrganisationTenancy);

        $this->app?->bind(Provisioner::class, ProvisionsPeople::class);

        $this->mapping = FakeGroupMapping::fake($this->app)
            ->map('finance', self::VIEWER)
            ->map('finance-ops', self::VIEWER, GrantInstruction::roleWithSubtree(self::APPROVER));
    }

    /**
     * A first sign-in reporting groups is provisioned a person holding, in the
     * connection's tenant, the roles the mapping answers for the groups, a
     * group it does not map giving nothing; and the person signs in.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAFirstSignInIsGrantedWhatItsGroupsMapTo(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $this->redeem($this->handoffWith(['finance-ops', 'engineering']));

        $person = Person::query()->sole();

        self::assertSame([self::APPROVER => true, self::VIEWER => false], $this->rolesOf($person, self::TENANT));
        self::assertSame([['connection' => $this->connectionId, 'tenant' => self::TENANT, 'groups' => ['finance-ops', 'engineering']]], $this->mapping()->asked());
    }

    /**
     * A single group, reported as one value, is mapped as a list of one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASingleGroupIsMapped(): void
    {
        $this->redeem($this->handoffWith('finance'));

        self::assertSame([self::VIEWER => false], $this->rolesOf(Person::query()->sole(), self::TENANT));
    }

    /**
     * A connection that reports no groups grants nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNoGroupsGrantNothing(): void
    {
        $this->redeem($this->handoffWith(null));

        self::assertSame([], $this->rolesOf(Person::query()->sole(), self::TENANT));
        self::assertSame([], $this->mapping()->asked()[0]['groups']);
    }

    /**
     * Groups that map to nothing grant nothing, and name no tenant to
     * `laravel-authorization`: the tenant resolver is not asked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testGroupsMappingToNothingNameNoTenant(): void
    {
        $resolver = \Mockery::mock(TenantResolver::class);

        $resolver->expects('resolve')->never();

        $this->app?->instance(TenantResolver::class, $resolver);

        $this->redeem($this->handoffWith(['engineering']));

        self::assertSame([], $this->rolesOf(Person::query()->sole(), self::TENANT));
    }

    /**
     * A mapping that refuses rolls the person, the membership and the link back
     * with it, and the completion fails with the refusal.
     *
     * @param  ?string  $level
     * @return void
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testARefusedMappingRollsTheProvisioningBack(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $refusal = new \RuntimeException('The groups cannot be mapped.');

        $this->mapping()->refuse($refusal);

        $this->assertProvisioningRolledBack($refusal, fn (): Handoff => $this->handoffWith(['finance']));
    }

    /**
     * A role the mapping names that does not exist rolls the provisioning back,
     * rather than provision a person without it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnknownRoleRollsTheProvisioningBack(): void
    {
        $this->mapping()->map('finance', 'no-such-role');

        try {
            $this->handoffWith(['finance']);

            self::fail('A person was provisioned without the role the groups map to.');
        } catch (\Throwable) {
            $this->assertNothingProvisioned();
        }
    }

    /**
     * Groups that map to both roles of a mutually exclusive pair refuse the
     * sign-in and roll the provisioning back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testGroupsMappingToExclusiveRolesRollTheProvisioningBack(): void
    {
        $this->app?->make(RoleExclusionService::class)->declare(self::VIEWER, self::APPROVER);

        try {
            $this->handoffWith(['finance-ops']);

            self::fail('A person was provisioned holding both roles of an exclusive pair.');
        } catch (\Throwable $exception) {
            self::assertInstanceOf(RoleExclusionConflictException::class, $exception);
            self::assertStringContainsString(sprintf('Roles \'%s\' and \'%s\'', self::VIEWER, self::APPROVER), $exception->getMessage());
        }

        $this->assertNothingProvisioned();
    }

    /**
     * With no mapping configured, nothing is granted, and the person is still
     * provisioned.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithNoMappingNothingIsGranted(): void
    {
        $this->app?->forgetInstance(FakeGroupMapping::MAPPING);
        $this->app?->offsetUnset(FakeGroupMapping::MAPPING);

        $this->redeem($this->handoffWith(['finance']));

        self::assertSame([], $this->rolesOf(Person::query()->sole(), self::TENANT));
    }

    /**
     * With the application's opt-in, a later sign-in re-syncs the person's
     * roles in the tenant to the groups it reports: a group added grants its
     * roles, a group removed revokes them, an unmapped group grants nothing, a
     * role granted to the person in the tenant that the mapping does not answer
     * is revoked, and one in another tenant is left alone.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testALaterSignInReSyncsTheGroups(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $this->app?->bind(GroupResync::class, MappedGroupResync::class);

        $this->redeem($this->handoffWith(['finance']));

        $person = Person::query()->sole();

        $this->grantDirectly($person, self::ADMIN, self::TENANT);
        $this->grantDirectly($person, self::ADMIN, 'tenant-2');

        $this->redeem($this->handoffWith(['finance-ops', 'engineering']));

        self::assertSame([self::APPROVER => true, self::VIEWER => false], $this->rolesOf($person, self::TENANT));
        self::assertSame([self::ADMIN => false], $this->rolesOf($person, 'tenant-2'));

        $this->redeem($this->handoffWith(['finance']));

        self::assertSame([self::VIEWER => false], $this->rolesOf($person, self::TENANT));

        $this->redeem($this->handoffWith(['engineering']));

        self::assertSame([], $this->rolesOf($person, self::TENANT));
        self::assertSame(1, Person::query()->count());
    }

    /**
     * A re-synced grant that widens the person's scope takes SSO's identity
     * guard only once the redemption, which locked the connection, the code and
     * the link, has committed, in a transaction of its own: SSO's lock order
     * puts the guard before every connection, so a guard taken under the
     * redemption's locks would deadlock with a change that holds the guard and
     * waits on the connection.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testTheReSyncTakesTheIdentityGuardOnlyOnceTheRedemptionHasCommitted(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $this->app?->bind(GroupResync::class, MappedGroupResync::class);

        $this->redeem($this->handoffWith(['finance']));

        $handoff     = $this->handoffWith(['finance-ops']);
        $transaction = 0;
        $statements  = [];

        Event::listen(TransactionBeginning::class, static function (TransactionBeginning $event) use (&$transaction): void {
            $transaction += $event->connection->transactionLevel() === 1 ? 1 : 0;
        });

        DB::listen(static function (QueryExecuted $query) use (&$transaction, &$statements): void {
            $statements[] = [$transaction, $query->sql];
        });

        $this->redeem($handoff);

        $codes  = self::transactionsTouching($statements, 'sso_handoff_codes');
        $guards = self::transactionsTouching($statements, 'sso_identity_guards');

        self::assertNotSame([], $codes);
        self::assertNotSame([], $guards, 'The re-synced grant took no identity guard.');
        self::assertSame([], array_intersect($codes, $guards), 'The identity guard was taken under the redemption\'s locks.');
        self::assertGreaterThan(max($codes), min($guards));
        self::assertSame([self::APPROVER => true, self::VIEWER => false], $this->rolesOf(Person::query()->sole(), self::TENANT));
    }

    /**
     * A re-sync runs once the sign-in has committed, in a transaction of its
     * own, so one that refuses grants and revokes nothing, and hands out no
     * credential: the sign-in, its session and the spent code stand, and the
     * code cannot be redeemed again.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testARefusedReSyncHandsOutNoCredential(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $this->app?->bind(GroupResync::class, MappedGroupResync::class);

        $this->redeem($this->handoffWith(['finance']));

        $person   = Person::query()->sole();
        $sessions = DB::table('authentication_sessions')->count();
        $handoff  = $this->handoffWith(['finance-ops']);
        $refusal  = new \RuntimeException('The groups cannot be re-synced.');

        $this->mapping()->refuse($refusal);

        try {
            Iam::signIns()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, new SignInContext(self::client()));

            self::fail('A sign-in whose re-sync refused handed out its credential.');
        } catch (\RuntimeException $exception) {
            self::assertSame($refusal, $exception);
        }

        self::assertSame([self::VIEWER => false], $this->rolesOf($person, self::TENANT));
        self::assertSame($sessions + 1, DB::table('authentication_sessions')->count());
        self::assertSame(0, DB::connection()->transactionLevel());

        $again = Iam::signIns()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, new SignInContext(self::client()));

        self::assertInstanceOf(RedemptionResult::class, $again);
        self::assertFalse($again->isRedeemed());
    }

    /**
     * A re-sync to both roles of a mutually exclusive pair is refused like any
     * other refused re-sync: nothing changes and no credential is handed out.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReSyncToExclusiveRolesHandsOutNoCredential(): void
    {
        $this->app?->bind(GroupResync::class, MappedGroupResync::class);

        $this->redeem($this->handoffWith(['finance']));

        $person  = Person::query()->sole();
        $handoff = $this->handoffWith(['finance-ops']);

        $this->app?->make(RoleExclusionService::class)->declare(self::VIEWER, self::APPROVER);

        try {
            Iam::signIns()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, new SignInContext(self::client()));

            self::fail('A sign-in whose re-sync broke a role exclusion handed out its credential.');
        } catch (RoleExclusionConflictException $exception) {
            self::assertStringContainsString(sprintf('Roles \'%s\' and \'%s\'', self::VIEWER, self::APPROVER), $exception->getMessage());
        }

        self::assertSame([self::VIEWER => false], $this->rolesOf($person, self::TENANT));
        self::assertSame(0, DB::connection()->transactionLevel());
    }

    /**
     * An application's own re-sync is handed the linked identity, the
     * connection, its tenant and the groups the later sign-in reports.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheApplicationsOwnReSyncIsHandedPlainValues(): void
    {
        $this->redeem($this->handoffWith(['finance']));

        $person = Person::query()->sole();
        $resync = \Mockery::mock(GroupResync::class);

        $resync->expects('resync')->once()->withArgs(fn (Person $identity, string $connectionId, string $tenantId, array $groups): bool => $identity->is($person)
            && $connectionId === $this->connectionId
            && $tenantId     === self::TENANT
            && $groups       === ['finance-ops']);

        $this->app?->instance(GroupResync::class, $resync);

        $this->redeem($this->handoffWith(['finance-ops']));
    }

    /**
     * With no re-sync configured, a later sign-in reporting other groups
     * changes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithNoReSyncALaterSignInChangesNothing(): void
    {
        $this->redeem($this->handoffWith(['finance']));

        $person = Person::query()->sole();

        $this->redeem($this->handoffWith(['finance-ops']));

        self::assertSame([self::VIEWER => false], $this->rolesOf($person, self::TENANT));
        self::assertCount(1, $this->mapping()->asked());
    }

    /**
     * Complete a `sign_in` flow whose provider reports the groups given (none
     * for `null`), and answer the handoff.
     *
     * @param  list<string>|string|null  $groups
     * @return \Tests\Fixtures\Sso\Handoff
     *
     * @throws \Random\RandomException
     */
    private function handoffWith(array|string|null $groups): Handoff
    {
        $tailor = static fn (FakeIdToken $token): FakeIdToken => $groups === null ? $token->without('groups') : $token->with('groups', $groups);

        return $this->handoff(Purpose::SIGN_IN, null, null, $tailor);
    }

    /**
     * Redeem the handoff, asserting it signs the person in.
     *
     * @param  \Tests\Fixtures\Sso\Handoff  $handoff
     * @return void
     *
     * @throws \Throwable
     */
    private function redeem(Handoff $handoff): void
    {
        $signedIn = Iam::signIns()->redeem(self::GUARD, $this->connectionId, $handoff->code, $handoff->verifier, new SignInContext(self::client()));

        self::assertInstanceOf(SignInResult::class, $signedIn);
        self::assertTrue($signedIn->isSignedIn());
    }

    /**
     * The outermost transactions, by the order they began, whose statements
     * name the table.
     *
     * @param  list<array{int, string}>  $statements
     * @param  string  $table
     * @return list<int>
     */
    private static function transactionsTouching(array $statements, string $table): array
    {
        $touching = array_filter($statements, static fn (array $statement): bool => $statement[0] > 0 && str_contains($statement[1], $table));

        return array_values(array_unique(array_column($touching, 0)));
    }

    /**
     * Grant the person the role in the tenant, as an administrator would.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  string  $role
     * @param  string  $tenantId
     * @return void
     *
     * @throws \Throwable
     */
    private function grantDirectly(Person $person, string $role, string $tenantId): void
    {
        $service = $this->app?->make(GrantService::class) ?? self::fail('The application has not booted.');

        Iam::transaction(static fn () => $service->grantRole($person, $role, tenant: new Reference(Organisation::TYPE, $tenantId), includeSubtree: false));
    }

    /**
     * The roles the person holds in the tenant, each by its name, with whether
     * it reaches the tenant's subtree, ordered by name.
     *
     * @param  \Tests\Fixtures\Models\Person  $person
     * @param  string  $tenantId
     * @return array<string, bool>
     */
    private function rolesOf(Person $person, string $tenantId): array
    {
        $rows = DB::table('authorizable_roles')
            ->join('roles', 'roles.id', '=', 'authorizable_roles.role_id')
            ->where('authorizable_roles.authorizable_type', $person->getMorphClass())
            ->where('authorizable_roles.authorizable_id', (string) $person->id)
            ->where('authorizable_roles.tenant_type', Organisation::TYPE)
            ->where('authorizable_roles.tenant_id', $tenantId)
            ->orderBy('roles.name')
            ->get(['roles.name', 'authorizable_roles.include_subtree']);

        $roles = [];

        foreach ($rows as $row) {

            self::assertIsString($row->name);

            $roles[$row->name] = filter_var($row->include_subtree, FILTER_VALIDATE_BOOL);
        }

        return $roles;
    }

    /**
     * Assert completing the flow throws the refusal given and provisions
     * nothing.
     *
     * @param  \Throwable  $refusal
     * @param  \Closure(): mixed  $complete
     * @return void
     */
    private function assertProvisioningRolledBack(\Throwable $refusal, \Closure $complete): void
    {
        try {
            $complete();

            self::fail('The provisioning went on past the refusal.');
        } catch (\Throwable $exception) {
            self::assertSame($refusal, $exception);
        }

        $this->assertNothingProvisioned();
    }

    /**
     * Assert no person, membership, link or role was left written.
     *
     * @return void
     */
    private function assertNothingProvisioned(): void
    {
        self::assertSame(0, Person::query()->count());
        self::assertSame(0, ProvisionedMembership::query()->count());
        self::assertSame(0, Link::query()->count());
        self::assertSame(0, DB::table('authorizable_roles')->count());
        self::assertSame(0, DB::connection()->transactionLevel());
    }

    /**
     * The application's group mapping.
     *
     * @return \SineMacula\Laravel\Iam\Testing\FakeGroupMapping
     */
    private function mapping(): FakeGroupMapping
    {
        return $this->mapping ?? self::fail('The mapping is not arranged.');
    }
}
