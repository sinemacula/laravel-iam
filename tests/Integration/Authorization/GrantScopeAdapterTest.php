<?php

declare(strict_types = 1);

namespace Tests\Integration\Authorization;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant;
use SineMacula\Laravel\Authorization\Contracts\IdentityDirectory;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Support\IdentityPrincipals;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Iam\Authorization\GrantScopeAdapter;
use SineMacula\Laravel\Iam\Authorization\IdentityDirectoryAdapter;
use SineMacula\Laravel\Iam\Authorization\Translation\TenantTranslator;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Tenancy\Contracts\GrantScope;
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
use Tests\Fixtures\Tenancy\StoredTenantTree;
use Tests\TestCase;

/**
 * Integration tests for the grant half of SSO's principal scope.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GrantScopeAdapter::class)]
#[CoversClass(IdentityDirectoryAdapter::class)]
#[CoversClass(TenantTranslator::class)]
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
     * The adapter is bound while authorization is on.
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
     * Rows of `[tenant of the grant, verdict]`; `false` for no grant.
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
     * A person who acts as themselves is placed by their own grants.
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
     * The judgement reads inside the caller's transaction.
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
     * A person is placed by their principals' grants too.
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
     * A principal hidden by a global scope still places its person.
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
     * An identity whose principals cannot be listed is unknown.
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
     * A grant below the tenant in the tree is within it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheTreePlacesAGrantBelowTheTenantWithinIt(): void
    {
        $this->placeOrganisations(['parent' => null, self::TENANT => 'parent', 'child' => self::TENANT]);

        [$below, $above] = [$this->createPerson(), $this->createPerson()];

        $this->grant($below, 'child');
        $this->grant($above, 'parent');

        self::assertSame(ScopeVerdict::WITHIN_TENANT, $this->judged($below, self::TENANT));
        self::assertSame(ScopeVerdict::OUTSIDE_TENANT, $this->judged($above, self::TENANT));
    }

    /**
     * A grant below the tenant in another tenant type is within it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGrantBelowTheTenantInATenantOfAnotherTypeIsWithinIt(): void
    {
        $account = new Reference(Account::TYPE, Account::PREFIX . '1');

        $this->placeOrganisations([self::TENANT => null, self::OTHER_TENANT => null]);

        StoredTenantTree::place($account, new Reference(Organisation::TYPE, self::TENANT));

        $this->app?->instance(TenantResolver::class, new AccountTenancy);

        $person  = $this->createPerson();
        $service = $this->app?->make(GrantService::class) ?? self::fail('The application has not booted.');

        $service->grantRole($person, self::ROLE, tenant: $account, includeSubtree: false);

        self::assertSame(ScopeVerdict::WITHIN_TENANT, $this->judged($person, self::TENANT));
        self::assertSame(ScopeVerdict::OUTSIDE_TENANT, $this->judged($person, self::OTHER_TENANT));
    }

    /**
     * A tenant that cannot be resolved throws.
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
     * A tenant authorization cannot read throws.
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
     * A tenant keyed otherwise than its identifier throws.
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
     * An identity the directory cannot resolve is an incomplete list.
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
     * Bind the application's tree, each organisation placed under its parent.
     *
     * @param  array<string, ?string>  $parents
     * @return void
     */
    private function placeOrganisations(array $parents): void
    {
        foreach ($parents as $tenantId => $parentId) {
            StoredTenantTree::place(new Reference(Organisation::TYPE, $tenantId), $parentId === null ? null : new Reference(Organisation::TYPE, $parentId));
        }

        $this->app?->instance(TenantTree::class, new StoredTenantTree);
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
     * Resolve the abstract from the container.
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
