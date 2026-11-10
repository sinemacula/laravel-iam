<?php

declare(strict_types = 1);

namespace Tests\Integration\Authorization;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Iam\Authorization\SubtreeGrantees;
use SineMacula\Laravel\Iam\Exceptions\TenancyMisconfiguredException;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Sso\SsoSeams;
use SineMacula\Laravel\Iam\Tenancy\TenancyContracts;
use SineMacula\Laravel\Iam\Tenancy\TreeChanges;
use SineMacula\Laravel\Iam\Testing\FakeTenantTree;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Models\Link;
use Tests\Concerns\MigratesAuthorization;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInPeople;
use Tests\Concerns\SignsInThroughLinks;
use Tests\Fixtures\Authorization\Account;
use Tests\Fixtures\Authorization\AccountTenancy;
use Tests\Fixtures\Authorization\Organisation;
use Tests\Fixtures\Authorization\OrganisationTenancy;
use Tests\Fixtures\Authorization\Seat;
use Tests\Fixtures\Authorization\SeatHolder;
use Tests\Fixtures\Authorization\Staff;
use Tests\Fixtures\Models\Person;
use Tests\TestCase;

/**
 * Integration tests for a move of the application's tree that widens the scope
 * of the people granted in the moved subtree (IAM-6.7, IAM-7.5): a person whose
 * grant is rooted below the tenant of their link by a verified domain is within
 * that tenant, and a move of the granted tenant out from under it takes their
 * grant beyond it with no grant written, so the move itself reports every
 * person granted in the moved subtree to SSO's scope widening, which suspends
 * the link and revokes the session established through it in the move's own
 * transaction, and rolls back with it; nothing is reported while the SSO
 * capability's switch is off; and the people granted are read from every grant
 * table as `laravel-authorization` holds them, each once, a principal's
 * identity for a principal, a grantee named by its morph alias as the model it
 * maps to, never a grant that has expired, one outside the subtree, one of
 * another tenant type, one to a role, or one to what is no model; and a move of
 * a subtree holding a tenant of another type is refused, and rolls back.
 *
 * The move's report takes SSO's identity guard and locks the connections
 * holding the person's links inside the move's transaction, so each scenario
 * that commits or rolls back runs at the connection's own level on every
 * engine, then at READ COMMITTED and REPEATABLE READ on MySQL and PostgreSQL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TreeChanges::class)]
#[CoversClass(SubtreeGrantees::class)]
#[WithConfig(TenancyContracts::TREE, FakeTenantTree::class, defer: false)]
final class TreeMoveWideningTest extends TestCase
{
    use MigratesAuthorization, RunsAtIsolationLevels, RunsSsoFlows, SignsInPeople, SignsInThroughLinks {
        SignsInThroughLinks::keyOf insteadof RunsSsoFlows;
        SignsInThroughLinks::referenceOf insteadof RunsSsoFlows;
        SignsInThroughLinks::signInMethods insteadof RunsSsoFlows;
    }

    /** @var string The tenant of the person's link by a verified domain. */
    private const string LINKED = 'linked';

    /** @var string The tenant below the linked one that the person is granted in, and that moves. */
    private const string GRANTED = 'granted';

    /** @var string The granted tenant's child, which moves with it. */
    private const string GRANTED_CHILD = 'granted-child';

    /** @var string The role granted. */
    private const string ROLE = 'editor';

    /** @var ?\SineMacula\Laravel\Iam\Testing\FakeTenantTree The application's tree. */
    private ?FakeTenantTree $tree = null;

    /** @var ?\Tests\Fixtures\Models\Person The person granted in the granted tenant. */
    private ?Person $person = null;

    /** @var string The person's link by a verified domain, in the linked tenant's connection. */
    private string $linkId = '';

    /** @var string The linked tenant's connection. */
    private string $linkedConnectionId = '';

    /**
     * Arrange SSO, the tree (the granted tenant and its child below the linked
     * tenant), the role, the person granted it in the granted tenant, and then
     * their link by a verified domain in the linked tenant's connection, which
     * the grant, rooted below that tenant, leaves within it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeSso();

        $this->tree = FakeTenantTree::fake($this->app)->place(self::LINKED)->place(self::GRANTED, self::LINKED)->place(self::GRANTED_CHILD, self::GRANTED);

        $this->app?->instance(TenantResolver::class, new OrganisationTenancy);

        Role::query()->create(['name' => self::ROLE]);

        $person       = $this->createPerson();
        $this->person = $person;

        $this->grant($person, self::GRANTED);

        $this->linkedConnectionId = $this->makeConnection(self::LINKED);
        $tenantConnection         = $this->connectionId;
        $this->connectionId       = $this->linkedConnectionId;
        $this->linkId             = (string) $this->linkThroughFlow($person)->linkId;
        $this->connectionId       = $tenantConnection;

        Link::query()->whereKey($this->linkId)->update(['provenance' => LinkOrigin::VERIFIED_DOMAIN->value]);
    }

    /**
     * A move that takes the granted tenant out from under the linked one,
     * reported in the move's transaction, suspends the person's link and
     * revokes the session established through it before the move commits.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAMoveOutFromUnderTheLinkedTenantSuspendsTheLinkInTheMovesTransaction(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $session = $this->signInThrough($this->person(), $this->linkedConnectionId, $this->linkId);
        $inside  = Iam::transaction(function () use ($session): array {

            $this->tree()->place(self::GRANTED);

            Iam::treeChanges()->changed(self::GRANTED);

            return [$this->link()->state, $this->stored($session)->getRevokedAt()];
        });

        self::assertSame(LinkState::SUSPENDED, $inside[0]);
        self::assertNotNull($inside[1]);
        self::assertSame(LinkState::SUSPENDED, $this->link()->state);
        self::assertNotNull($this->stored($session)->getRevokedAt());
    }

    /**
     * A move that rolls back takes the suspension and the revocation back with
     * it.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAMoveThatRollsBackSuspendsNothing(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $session  = $this->signInThrough($this->person(), $this->linkedConnectionId, $this->linkId);
        $rollback = new \RuntimeException('The move is abandoned.');

        try {
            Iam::transaction(function () use ($rollback): never {

                Iam::treeChanges()->changed(self::GRANTED);

                self::assertSame(LinkState::SUSPENDED, $this->link()->state);

                throw $rollback;
            });
        } catch (\RuntimeException $exception) {
            self::assertSame($rollback, $exception);
        }

        self::assertSame(LinkState::ACTIVE, $this->link()->state);
        self::assertNull($this->stored($session)->getRevokedAt());
    }

    /**
     * With the SSO capability's switch off, `laravel-authorization`'s grants
     * are not reported to SSO, so a move reports nobody, and no grant is read.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithTheSsoSwitchOffNobodyIsReported(): void
    {
        Config::set(SsoSeams::SWITCH, false);

        $reads = 0;

        DB::listen(static function (QueryExecuted $query) use (&$reads): void {
            $reads += str_contains($query->sql, 'authorizable_') ? 1 : 0;
        });

        Iam::transaction(static fn (): int => Iam::treeChanges()->changed(self::GRANTED));

        self::assertSame(LinkState::ACTIVE, $this->link()->state);
        self::assertSame(0, $reads);
    }

    /**
     * The people granted in the subtree are read from every grant table, each
     * once: a role, a permission and a policy to the person, in the tenant and
     * below it, answer them once; another person, and an identity of another
     * type that shares the person's key, answer themselves; a principal's grant
     * answers its identity; a grant that has expired, one outside the subtree,
     * one of another tenant type, one to a role, one to a grantee that is no
     * model, and one to a grantee whose row is gone answer nobody.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThePeopleGrantedAreReadFromEveryGrantTableEachOnce(): void
    {
        $service = $this->app?->make(GrantService::class) ?? self::fail('The application has not booted.');
        $holder  = SeatHolder::query()->create(['name' => 'Grace Hopper', 'email' => 'grace@example.test']);
        $seat    = Seat::query()->create(['person_id' => $holder->id, 'tenant_id' => self::GRANTED_CHILD]);
        $expired = $this->createPerson();
        $outside = $this->createPerson();
        $other   = $this->createPerson();
        $gone    = $this->createPerson();

        $service->grantRole($seat, self::ROLE, tenant: self::organisation(self::GRANTED_CHILD), includeSubtree: false);
        $service->grantRole($outside, self::ROLE, tenant: self::organisation(self::LINKED), includeSubtree: false);
        $service->grantRole($expired, self::ROLE, tenant: self::organisation(self::GRANTED), includeSubtree: false, expiresAt: CarbonImmutable::now()->addMinute());
        $service->grantRole($gone, self::ROLE, tenant: self::organisation(self::GRANTED), includeSubtree: false);

        $this->travel(2)->minutes();

        $another = $this->createPerson();
        $staff   = Staff::query()->whereKey(self::keyOf($this->person()))->firstOrFail();
        $grants  = [
            ['authorizable_permissions', $this->person()->getMorphClass(), self::keyOf($this->person()), self::GRANTED_CHILD, Organisation::TYPE],
            ['authorizable_policies', $this->person()->getMorphClass(), self::keyOf($this->person()), self::GRANTED, Organisation::TYPE],
            ['authorizable_permissions', $other->getMorphClass(), self::keyOf($other), self::GRANTED, 'another-type'],
            ['authorizable_roles', $another->getMorphClass(), self::keyOf($another), self::GRANTED_CHILD, Organisation::TYPE],
            ['authorizable_roles', $staff->getMorphClass(), self::keyOf($staff), self::GRANTED, Organisation::TYPE],
            ['authorizable_roles', (new Role)->getMorphClass(), self::keyOf(Role::query()->firstOrFail()), self::GRANTED, Organisation::TYPE],
            ['authorizable_roles', 'no-such-model', '1', self::GRANTED, Organisation::TYPE],
        ];

        foreach ($grants as [$table, $type, $id, $tenantId, $tenantType]) {
            DB::table($table)->insert([
                self::foreignColumn($table) => self::foreignKey($table),
                'authorizable_type'         => $type,
                'authorizable_id'           => $id,
                'tenant_type'               => $tenantType,
                'tenant_id'                 => $tenantId,
            ]);
        }

        DB::table($gone->getTable())->where('id', self::keyOf($gone))->delete();

        $identities = $this->grantees()->of(self::GRANTED);
        $found      = array_map(static fn (object $identity): string => $identity::class . ':' . ($identity instanceof Model ? self::keyOf($identity) : ''), $identities);

        self::assertSame(array_keys($identities), range(0, count($identities) - 1));

        sort($found);

        $expected = [
            Person::class . ':' . self::keyOf($this->person()),
            Person::class . ':' . self::keyOf($another),
            Staff::class . ':' . self::keyOf($staff),
            $seat->getIdentity()::class . ':' . self::keyOf($holder),
        ];

        sort($expected);

        self::assertSame($expected, $found);
    }

    /**
     * A move of a subtree holding a tenant of another type, an account below
     * the granted organisation, is refused, and rolls back: the grants rooted
     * in the account would never be matched by the organisation's type, and the
     * people granted there would go unreported to SSO's widening.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAMoveOfASubtreeHoldingAnotherTenantTypeIsRefused(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $account = Account::PREFIX . '1';

        $this->app?->instance(TenantResolver::class, new AccountTenancy);
        $this->tree()->place($account, self::GRANTED_CHILD);

        $refused = null;

        try {
            Iam::transaction(function (): void {

                $this->tree()->place(self::GRANTED);

                Iam::treeChanges()->changed(self::GRANTED);
            });
        } catch (\Throwable $exception) {
            $refused = $exception;
        }

        self::assertInstanceOf(TenancyMisconfiguredException::class, $refused);
        self::assertStringContainsString('[' . Account::TYPE . ']', $refused->getMessage());
        self::assertSame(LinkState::ACTIVE, $this->link()->state);
    }

    /**
     * The grant tables are read under the names `authorization.tables` gives
     * them.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheGrantTablesAreReadUnderTheirConfiguredNames(): void
    {
        Config::set('authorization.tables.authorizable_roles', 'renamed_roles');

        try {
            $this->grantees()->of(self::GRANTED);

            self::fail('A grant table was read under its default name.');
        } catch (QueryException $exception) {
            self::assertStringContainsString('renamed_roles', $exception->getSql());
        } finally {
            // The migrations roll back under the name the table was created
            // with
            Config::set('authorization.tables.authorizable_roles', 'authorizable_roles');
        }
    }

    /**
     * A grantee named by its morph alias is read as the model the alias maps
     * to.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGranteeNamedByItsMorphAliasIsRead(): void
    {
        $before = Relation::morphMap();

        Relation::morphMap(['granted-staff' => Staff::class]);

        try {
            DB::table('authorizable_roles')->insert([
                'role_id'           => Role::query()->value('id'),
                'authorizable_type' => 'granted-staff',
                'authorizable_id'   => self::keyOf($this->person()),
                'tenant_type'       => Organisation::TYPE,
                'tenant_id'         => self::GRANTED_CHILD,
            ]);

            $classes = array_map(static fn (object $identity): string => $identity::class, $this->grantees()->of(self::GRANTED_CHILD));
        } finally {
            Relation::morphMap($before, false);
        }

        self::assertContains(Staff::class, $classes);
    }

    /**
     * Grant the role to the grantee in the tenant alone.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $grantee
     * @param  string  $tenantId
     * @return void
     *
     * @throws \Throwable
     */
    private function grant(Model $grantee, string $tenantId): void
    {
        $service = $this->app?->make(GrantService::class) ?? self::fail('The application has not booted.');

        $service->grantRole($grantee, self::ROLE, tenant: self::organisation($tenantId), includeSubtree: false);
    }

    /**
     * The column of the table given that holds what is granted.
     *
     * @param  string  $table
     * @return string
     */
    private static function foreignColumn(string $table): string
    {
        return match ($table) {
            'authorizable_roles'       => 'role_id',
            'authorizable_permissions' => 'permission_id',
            default                    => 'policy_id',
        };
    }

    /**
     * The key of a role, a permission or a policy, for a row of the table
     * given, stored on first use.
     *
     * @param  string  $table
     * @return string
     */
    private static function foreignKey(string $table): string
    {
        if ($table === 'authorizable_roles') {
            return self::keyOf(Role::query()->firstOrFail());
        }

        if ($table === 'authorizable_permissions') {
            return self::keyOf(Permission::query()->firstOrCreate(['name' => 'invoices:refund']));
        }

        $existing = DB::table('policies')->value('id');

        if (is_string($existing)) {
            return $existing;
        }

        $id = (string) Str::uuid();

        DB::table('policies')->insert(['id' => $id, 'name' => 'refunds', 'is_system' => false, 'document' => '{"statements":[]}']);

        return $id;
    }

    /**
     * The people granted in a subtree, as the move reads them.
     *
     * @return \SineMacula\Laravel\Iam\Authorization\SubtreeGrantees
     */
    private function grantees(): SubtreeGrantees
    {
        return $this->app?->make(SubtreeGrantees::class) ?? self::fail('The application has not booted.');
    }

    /**
     * The person granted in the granted tenant.
     *
     * @return \Tests\Fixtures\Models\Person
     */
    private function person(): Person
    {
        return $this->person ?? self::fail('No person is arranged.');
    }

    /**
     * The application's tree.
     *
     * @return \SineMacula\Laravel\Iam\Testing\FakeTenantTree
     */
    private function tree(): FakeTenantTree
    {
        return $this->tree ?? self::fail('The tree is not arranged.');
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

    /**
     * `laravel-authorization`'s reference to the organisation of the id.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     */
    private static function organisation(string $id): Reference
    {
        return new Reference(Organisation::TYPE, $id);
    }
}
