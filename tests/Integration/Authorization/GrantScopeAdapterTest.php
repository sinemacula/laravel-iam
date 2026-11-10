<?php

declare(strict_types = 1);

namespace Tests\Integration\Authorization;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant;
use SineMacula\Laravel\Authorization\Contracts\IdentityDirectory;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Support\IdentityPrincipals;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Iam\Authorization\GrantScopeAdapter;
use SineMacula\Laravel\Iam\Authorization\IdentityDirectoryAdapter;
use SineMacula\Laravel\Iam\Authorization\TenantTreeAdapter;
use SineMacula\Laravel\Iam\Authorization\Translation\TenantTranslator;
use SineMacula\Laravel\Iam\Contracts\TenantTree as ApplicationTree;
use SineMacula\Laravel\Iam\Exceptions\TenancyMisconfiguredException;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Tenancy\Contracts\GrantScope;
use SineMacula\Laravel\Iam\Testing\FakeTenantTree;
use SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict;
use Tests\Concerns\MigratesAuthorization;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Authorization\Account;
use Tests\Fixtures\Authorization\AccountTenancy;
use Tests\Fixtures\Authorization\ArchivedSeat;
use Tests\Fixtures\Authorization\ArchivingSeatHolder;
use Tests\Fixtures\Authorization\OpaqueSeatHolder;
use Tests\Fixtures\Authorization\Organisation;
use Tests\Fixtures\Authorization\OrganisationTenancy;
use Tests\Fixtures\Authorization\Seat;
use Tests\Fixtures\Authorization\SeatHolder;
use Tests\Fixtures\Authorization\Staff;
use Tests\Fixtures\Resolvers\ClaimedTenant;
use Tests\TestCase;

/**
 * Integration tests for the grant half of SSO's principal scope, answered by
 * `laravel-authorization`'s grant scope query (IAM-6.8, AUTHZ-14.2), with the
 * identity's principals listed from `laravel-authentication`'s
 * (`IdentityDirectoryAdapter`) and the tenant tree the application's
 * (`TenantTreeAdapter`): a person who acts as themselves and holds no grant, or
 * grants only in the tenant or below it, is `within_tenant`; one granted in
 * another tenant, an ancestor of it or platform-wide is `outside_tenant`; a
 * person who owns principals is placed by their principals' grants too; a
 * tenant that cannot be resolved, or that `laravel-authorization` cannot read,
 * throws, as does a tree nesting two tenant types that would place a grant
 * below the tenant outside it; and the identity directory answers an identity
 * it cannot resolve as an incomplete list.
 *
 * The query reads on the write connection, in a savepoint of the caller's
 * transaction, as SSO asks it inside its own, so each judgement runs inside one
 * at the connection's own level on every engine, then at READ COMMITTED and
 * REPEATABLE READ on MySQL and PostgreSQL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GrantScopeAdapter::class)]
#[CoversClass(IdentityDirectoryAdapter::class)]
#[CoversClass(TenantTranslator::class)]
#[CoversClass(TenantTreeAdapter::class)]
final class GrantScopeAdapterTest extends TestCase
{
    use MigratesAuthorization, RunsAtIsolationLevels, SignsInPeople;

    /** @var string The tenant asked about. */
    private const string TENANT = 'tenant-1';

    /** @var string Another tenant. */
    private const string OTHER_TENANT = 'tenant-2';

    /** @var string The role granted. */
    private const string ROLE = 'editor';

    /**
     * Store the role, and resolve every tenant to the organisation of its id.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Role::query()->create(['name' => self::ROLE]);

        $this->app?->instance(TenantResolver::class, new OrganisationTenancy);
    }

    /**
     * The adapter is the grant half bound while the authorization capability is
     * on.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheAdapterIsTheBoundGrantHalf(): void
    {
        self::assertInstanceOf(GrantScopeAdapter::class, $this->resolved(GrantScope::class));
        self::assertInstanceOf(IdentityDirectoryAdapter::class, $this->resolved(IdentityDirectory::class));
    }

    /**
     * Rows of `[tenant of the grant, verdict]`: where a person who acts as
     * themselves holds a grant, and where that places them against the
     * tenant; `false` for no grant at all.
     *
     * @return iterable<string, array{0: false|string|null, 1: \SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict}>
     */
    public static function provideGrants(): iterable
    {
        yield 'no grant' => [false, ScopeVerdict::WITHIN_TENANT];

        yield 'a grant in the tenant' => [self::TENANT, ScopeVerdict::WITHIN_TENANT];

        yield 'a grant in another tenant' => [self::OTHER_TENANT, ScopeVerdict::OUTSIDE_TENANT];

        yield 'a platform-wide grant' => [null, ScopeVerdict::OUTSIDE_TENANT];
    }

    /**
     * A person who acts as themselves is placed by their own grants alone,
     * their list of principals complete and empty.
     *
     * @param  false|string|null  $granted
     * @param  \SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict  $verdict
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideGrants')]
    public function testAPersonIsPlacedByTheirGrants(false|string|null $granted, ScopeVerdict $verdict): void
    {
        $person = $this->createPerson();

        if ($granted !== false) {
            $this->grant($person, $granted);
        }

        self::assertSame($verdict, $this->judged($person, self::TENANT));
    }

    /**
     * Inside SSO's transaction, at every isolation level, a person granted only
     * in the tenant is within it, and one granted beyond it too is outside it.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testTheJudgementReadsInsideTheCallersTransaction(?string $level): void
    {
        self::runAtIsolationLevel($level);

        [$within, $outside] = [$this->createPerson(), $this->createPerson()];

        $this->grant($within, self::TENANT);
        $this->grant($outside, self::TENANT);
        $this->grant($outside, self::OTHER_TENANT);

        [$inside, $beyond] = DB::transaction(fn (): array => [$this->judged($within, self::TENANT), $this->judged($outside, self::TENANT)]);

        self::assertSame(ScopeVerdict::WITHIN_TENANT, $inside);
        self::assertSame(ScopeVerdict::OUTSIDE_TENANT, $beyond);
    }

    /**
     * A person who owns principals is placed by their principals' grants too: a
     * seat of another tenant holding a grant there places them outside the
     * tenant, and seats granted only in the tenant leave them within it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPersonIsPlacedByTheirPrincipalsGrants(): void
    {
        $holder = SeatHolder::query()->create(['name' => 'Grace Hopper', 'email' => 'grace@example.test']);
        $seat   = Seat::query()->create(['person_id' => $holder->id, 'tenant_id' => self::TENANT]);
        $other  = Seat::query()->create(['person_id' => $holder->id, 'tenant_id' => self::OTHER_TENANT]);

        $this->grant($seat, self::TENANT);

        self::assertSame(ScopeVerdict::WITHIN_TENANT, $this->judged($holder, self::TENANT));

        $this->grant($other, self::OTHER_TENANT);

        self::assertSame(ScopeVerdict::OUTSIDE_TENANT, $this->judged($holder, self::TENANT));
        self::assertEquals(IdentityPrincipals::complete([Reference::of($seat), Reference::of($other)]), $this->directory()->principalsOf(Reference::of($holder)));
    }

    /**
     * A principal the model's global scope hides, an archived seat, still holds
     * its grants, and places its person outside the tenant: the directory lists
     * it, so restoring it never widens the person's scope without a grant being
     * written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPrincipalAGlobalScopeHidesStillPlacesItsPerson(): void
    {
        $holder   = ArchivingSeatHolder::query()->create(['name' => 'Grace Hopper', 'email' => 'grace@example.test']);
        $seat     = ArchivedSeat::query()->create(['person_id' => $holder->id, 'tenant_id' => self::TENANT]);
        $archived = ArchivedSeat::query()->create(['person_id' => $holder->id, 'tenant_id' => self::OTHER_TENANT]);

        $this->grant($seat, self::TENANT);
        $this->grant($archived, self::OTHER_TENANT);

        $archived->delete();

        self::assertSame(ScopeVerdict::OUTSIDE_TENANT, $this->judged($holder, self::TENANT));
        self::assertEquals(IdentityPrincipals::complete([Reference::of($seat), Reference::of($archived)]), $this->directory()->principalsOf(Reference::of($holder)));
    }

    /**
     * An identity that is neither a principal itself nor owns principals has
     * them from a principal resolver the application binds, which the directory
     * cannot list, as has one whose principals are listed by no Eloquent query:
     * each list is incomplete, and the person is `unknown`, never
     * `within_tenant`, however their principals are granted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityWhosePrincipalsCannotBeListedIsUnknown(): void
    {
        $staff  = Staff::query()->create(['name' => 'Grace Hopper', 'email' => 'grace@example.test']);
        $opaque = OpaqueSeatHolder::query()->create(['name' => 'Ada Lovelace', 'email' => 'ada@example.test']);

        $this->grant(Seat::query()->create(['person_id' => $staff->id, 'tenant_id' => self::OTHER_TENANT]), self::OTHER_TENANT);

        self::assertSame(ScopeVerdict::UNKNOWN, $this->judged($staff, self::TENANT));
        self::assertSame(ScopeVerdict::UNKNOWN, $this->judged($opaque, self::TENANT));
        self::assertEquals(IdentityPrincipals::incomplete(), $this->directory()->principalsOf(Reference::of($staff)));
        self::assertEquals(IdentityPrincipals::incomplete(), $this->directory()->principalsOf(Reference::of($opaque)));
    }

    /**
     * Below the tenant in the application's tree is within it, and at its
     * parent is outside it, as `laravel-authorization` reads the tree through
     * this package's adapter.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheTreePlacesAGrantBelowTheTenantWithinIt(): void
    {
        FakeTenantTree::fake($this->app)->place('parent')->place(self::TENANT, 'parent')->place('child', self::TENANT);

        [$below, $above] = [$this->createPerson(), $this->createPerson()];

        $this->grant($below, 'child');
        $this->grant($above, 'parent');

        self::assertSame(ScopeVerdict::WITHIN_TENANT, $this->judged($below, self::TENANT));
        self::assertSame(ScopeVerdict::OUTSIDE_TENANT, $this->judged($above, self::TENANT));
    }

    /**
     * A grant below the tenant in a tenant of another type, an account placed
     * below an organisation once granted (a grant in it is refused while it is
     * there), is never read as outside it: the subtree names every tenant by
     * the organisation's type, so the query, missing the account's grant,
     * answers `outside`, and the tree is refused rather than have SSO suspend a
     * link for it. A grant outside a tree of one type is still outside.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGrantBelowTheTenantInATenantOfAnotherTypeIsRefused(): void
    {
        $account = Account::PREFIX . '1';

        $tree = FakeTenantTree::fake($this->app)->place(self::TENANT)->place(self::OTHER_TENANT)->place($account);

        $this->app?->instance(TenantResolver::class, new AccountTenancy);

        [$below, $beyond] = [$this->createPerson(), $this->createPerson()];

        $service = $this->app?->make(GrantService::class) ?? self::fail('The application has not booted.');

        $service->grantRole($below, self::ROLE, tenant: new Reference(Account::TYPE, $account), includeSubtree: false);

        $this->grant($beyond, self::TENANT);

        $tree->place($account, self::TENANT);

        self::assertSame(ScopeVerdict::WITHIN_TENANT, $this->judged($beyond, self::TENANT));
        self::assertSame(ScopeVerdict::OUTSIDE_TENANT, $this->judged($beyond, self::OTHER_TENANT));

        $this->expectException(TenancyMisconfiguredException::class);

        $this->judged($below, self::TENANT);
    }

    /**
     * A tree whose subtree selects its tenants' ids as integers, as one over an
     * integer key does, places a person granted only in the tenant within it,
     * at every isolation level: the ids are compared with
     * `laravel-authorization`'s text columns as text, which PostgreSQL
     * otherwise refuses.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testATreeOfIntegerIdsPlacesAGrantInTheTenantWithinIt(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $tree = \Mockery::mock(ApplicationTree::class);

        $tree->allows('ancestors')->andReturn([]);
        $tree->allows('isWithin')->andReturnUsing(static fn (string $tenantId, string $ancestorId): bool => $tenantId === $ancestorId);
        $tree->allows('subtree')->andReturnUsing(static fn (string $tenantId): Builder => DB::query()->selectRaw('? + 0 as ' . ApplicationTree::ID_COLUMN, [(int) $tenantId]));

        $this->app?->instance(ApplicationTree::class, $tree);

        $person = $this->createPerson();

        $this->grant($person, '7');

        self::assertSame(ScopeVerdict::WITHIN_TENANT, DB::transaction(fn (): ScopeVerdict => $this->judged($person, '7')));
    }

    /**
     * A tree `laravel-authorization` cannot read leaves a person granted only
     * in a tenant of it `unknown`, never `within_tenant`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATreeThatCannotBeReadIsUnknown(): void
    {
        $tree   = FakeTenantTree::fake($this->app)->place(self::TENANT);
        $person = $this->createPerson();

        $this->grant($person, self::TENANT);

        $tree->failFor(self::TENANT);

        self::assertSame(ScopeVerdict::UNKNOWN, $this->judged($person, self::TENANT));
    }

    /**
     * A tenant `laravel-authentication`'s resolver does not resolve throws,
     * with nothing judged.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantThatCannotBeResolvedThrows(): void
    {
        $resolver = \Mockery::mock(TenantResolver::class);

        $resolver->allows('resolve')->andReturnNull();

        $this->app?->instance(TenantResolver::class, $resolver);

        $this->expectException(UnresolvedReferenceException::class);

        $this->judged($this->createPerson(), self::TENANT);
    }

    /**
     * A tenant `laravel-authorization` cannot read, one that is neither an
     * Eloquent model nor its authorizable tenant, throws.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantAuthorizationCannotReadThrows(): void
    {
        $resolver = \Mockery::mock(TenantResolver::class);

        $resolver->allows('resolve')->andReturnUsing(static fn (string $id): object => new class ($id) implements Tenant {
            /**
             * Constructor.
             *
             * @param  string  $id
             */
            public function __construct(

                /** The tenant's id. */
                private readonly string $id,
            ) {}

            /**
             * The tenant's id.
             *
             * @return string
             */
            #[\Override]
            public function getTenantIdentifier(): string
            {
                return $this->id;
            }
        });

        $this->app?->instance(TenantResolver::class, $resolver);

        $this->expectException(UnresolvedReferenceException::class);

        $this->judged($this->createPerson(), self::TENANT);
    }

    /**
     * A tenant whose key is not its identifier names another tenant to
     * `laravel-authorization`, and throws.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantKeyedOtherwiseThanItsIdentifierThrows(): void
    {
        $resolver = \Mockery::mock(TenantResolver::class);
        $tenant   = \Mockery::mock(Tenant::class, AuthorizableTenant::class);

        $tenant->allows('getTenantIdentifier')->andReturn(self::TENANT);
        $tenant->allows('getKey')->andReturn('17');
        $tenant->allows('getMorphClass')->andReturn(Organisation::TYPE);
        $resolver->allows('resolve')->andReturn($tenant);

        $this->app?->instance(TenantResolver::class, $resolver);

        $this->expectException(UnresolvedReferenceException::class);

        $this->judged($this->createPerson(), self::TENANT);
    }

    /**
     * An identity the directory cannot resolve, of a type no identity model is,
     * or of no stored row, is answered as an incomplete list, never as a
     * complete one.
     *
     * @return void
     */
    public function testAnIdentityTheDirectoryCannotResolveIsIncomplete(): void
    {
        self::assertEquals(IdentityPrincipals::incomplete(), $this->directory()->principalsOf(new Reference(ClaimedTenant::TYPE, '1')));
        self::assertEquals(IdentityPrincipals::incomplete(), $this->directory()->principalsOf(new Reference($this->createPerson()->getMorphClass(), '')));
        self::assertEquals(IdentityPrincipals::incomplete(), $this->directory()->principalsOf(new Reference($this->createPerson()->getMorphClass(), '999999')));
    }

    /**
     * Grant the role to the grantee in the tenant given, or platform-wide.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $grantee
     * @param  ?string  $tenantId
     * @return void
     *
     * @throws \Throwable
     */
    private function grant(Model $grantee, ?string $tenantId): void
    {
        $service = $this->app?->make(GrantService::class) ?? self::fail('The application has not booted.');

        $service->grantRole($grantee, self::ROLE, tenant: $tenantId === null ? null : new Reference(Organisation::TYPE, $tenantId), includeSubtree: false);
    }

    /**
     * Where the bound grant half places the identity against the tenant.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $tenantId
     * @return \SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict
     *
     * @throws \Throwable
     */
    private function judged(Identity $identity, string $tenantId): ScopeVerdict
    {
        $scope = $this->app?->make(GrantScope::class) ?? self::fail('The application has not booted.');

        return $scope->judge($identity, $tenantId);
    }

    /**
     * The bound identity directory.
     *
     * @return \SineMacula\Laravel\Authorization\Contracts\IdentityDirectory
     */
    private function directory(): IdentityDirectory
    {
        return $this->app?->make(IdentityDirectory::class) ?? self::fail('The application has not booted.');
    }

    /**
     * What the container resolves the abstract to, as anything that asks for it
     * does.
     *
     * @param  string  $abstract
     * @return mixed
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function resolved(string $abstract): mixed
    {
        return $this->app?->make($abstract);
    }
}
