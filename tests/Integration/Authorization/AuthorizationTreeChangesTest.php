<?php

declare(strict_types = 1);

namespace Tests\Integration\Authorization;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Support\Facades\DB;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Resolvers\FlatTenantTree;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Facades\Iam;
use SineMacula\Laravel\Iam\Tenancy\TreeChanges;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Models\Link;
use Tests\Concerns\MigratesAuthorization;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Concerns\RunsSsoFlows;
use Tests\Concerns\SignsInPeople;
use Tests\Fixtures\Authorization\Account;
use Tests\Fixtures\Authorization\AccountTenancy;
use Tests\Fixtures\Authorization\Enums\InvoicePermission;
use Tests\Fixtures\Authorization\Member;
use Tests\Fixtures\Authorization\Organisation;
use Tests\Fixtures\Authorization\Seat;
use Tests\Fixtures\Authorization\SeatHolder;
use Tests\Fixtures\Authorization\Staff;
use Tests\Fixtures\Tenancy\StoredTenantTree;
use Tests\TestCase;

/**
 * Integration tests for `laravel-authorization` reading the application's
 * tenant tree (IAM-7.5, AUTHZ-12.8): a grant reaches the tenants below it of
 * whatever type, and a move reported through `Iam::treeChanges()` reaches
 * `laravel-authorization` at once, reporting the identities granted in the
 * moved subtree to SSO's scope widening, while a flat tree reports nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TreeChanges::class)]
#[WithConfig('authorization.tenant_tree', StoredTenantTree::class, defer: false)]
final class AuthorizationTreeChangesTest extends TestCase
{
    use MigratesAuthorization, RunsAtIsolationLevels, RunsSsoFlows, SignsInPeople;

    /** @var string The organisation granted at. */
    private const string ROOT = 'organisation-1';

    /** @var string The organisation that moves below it. */
    private const string MOVED = 'organisation-2';

    /** @var string The account below the moved organisation. */
    private const string ACCOUNT = Account::PREFIX . '1';

    /**
     * Arrange the root apart from the moved organisation and its account, and
     * declare the invoice permissions.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        StoredTenantTree::place(self::tenant(self::ROOT));
        StoredTenantTree::place(self::tenant(self::MOVED));
        StoredTenantTree::place(self::tenant(self::ACCOUNT), self::tenant(self::MOVED));

        $this->app?->instance(TenantResolver::class, new AccountTenancy);

        foreach (InvoicePermission::cases() as $permission) {
            Permission::query()->create(['name' => $permission->value]);
        }
    }

    /**
     * A grant at an organisation reaches the account below it, a tenant of
     * another type.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGrantReachesATenantOfAnotherTypeBelowIt(): void
    {
        $person = $this->grantedAt(self::MOVED);

        self::assertTrue($this->mayRefundIn($person, self::ACCOUNT));
    }

    /**
     * A reported move reaches `laravel-authorization`: a grant at the new
     * ancestor holds in the moved organisation and its account once reported,
     * not before.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAReportedMoveReachesAuthorization(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person = $this->grantedAt(self::ROOT);

        self::assertFalse($this->mayRefundIn($person, self::MOVED));

        StoredTenantTree::place(self::tenant(self::MOVED), self::tenant(self::ROOT));

        self::assertFalse($this->mayRefundIn($person, self::MOVED), 'laravel-authorization read the tree afresh without the move being reported.');

        self::assertSame(0, Iam::transaction(static fn (): int => Iam::treeChanges()->changed(self::MOVED)));

        self::assertTrue($this->mayRefundIn($person, self::MOVED));
        self::assertTrue($this->mayRefundIn($person, self::ACCOUNT));
    }

    /**
     * A move reports the identity behind each grantee in the moved subtree to
     * SSO's scope widening: an identity named by its morph alias, and a
     * principal's identity; a grantee that is no model, a role and one whose
     * row is gone are passed over, and nobody else is reported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMoveReportsTheIdentityBehindEachGranteeInTheSubtree(): void
    {
        $before = Relation::morphMap();

        Relation::morphMap(['granted-staff' => Staff::class]);

        try {
            $this->arrangeSso();

            $person = $this->createPerson();
            $gone   = $this->createPerson();
            $staff  = Staff::query()->whereKey($this->createPerson()->getKey())->firstOrFail();
            $holder = SeatHolder::query()->create(['name' => 'Grace Hopper', 'email' => 'grace@example.test']);
            $seat   = Seat::query()->create(['person_id' => $holder->id, 'tenant_id' => self::ACCOUNT]);
            $role   = Role::query()->create(['name' => 'editor']);

            $personLink = Link::query()->findOrFail((string) $this->linkThroughFlow($person)->linkId);

            $personLink->provenance = LinkOrigin::VERIFIED_DOMAIN;

            $personLink->save();

            $staffLink = self::copyLink($personLink, $staff);
            $seatLink  = self::copyLink($personLink, $seat->getIdentity());

            $grantees = [
                ['App\Missing', '1'],
                [$role->getMorphClass(), self::keyOf($role)],
                [$gone->getMorphClass(), self::keyOf($gone)],
                [$seat->getMorphClass(), self::keyOf($seat)],
                [$staff->getMorphClass(), self::keyOf($staff)],
            ];

            foreach ($grantees as [$type, $id]) {
                DB::table('authorizable_permissions')->insert([
                    'permission_id'     => Permission::query()->value('id'),
                    'authorizable_type' => $type,
                    'authorizable_id'   => $id,
                    'tenant_type'       => Account::TYPE,
                    'tenant_id'         => self::ACCOUNT,
                ]);
            }

            $gone->delete();

            Iam::transaction(static fn (): int => Iam::treeChanges()->changed(self::MOVED));
        } finally {
            Relation::morphMap($before, false);
        }

        self::assertSame(LinkState::SUSPENDED, $staffLink->refresh()->state);
        self::assertSame(LinkState::SUSPENDED, $seatLink->refresh()->state);
        self::assertSame(LinkState::ACTIVE, $personLink->refresh()->state);
    }

    /**
     * With `laravel-authorization`'s flat tree nothing is reported to it, and
     * no tenant is resolved for it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithAFlatTreeNothingIsReported(): void
    {
        $resolver = \Mockery::mock(TenantResolver::class);

        $resolver->expects('resolve')->never();

        $this->app?->instance(TenantResolver::class, $resolver);
        $this->app?->instance(TenantTree::class, new FlatTenantTree);

        self::assertSame(0, Iam::transaction(static fn (): int => Iam::treeChanges()->changed(self::MOVED)));
    }

    /**
     * A moved tenant that cannot be named to `laravel-authorization` refuses
     * the move.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantThatCannotBeNamedRefusesTheMove(): void
    {
        $resolver = \Mockery::mock(TenantResolver::class);

        $resolver->allows('resolve')->andReturnNull();

        $this->app?->instance(TenantResolver::class, $resolver);

        $this->expectException(UnresolvedReferenceException::class);

        Iam::transaction(static fn (): int => Iam::treeChanges()->changed(self::MOVED));
    }

    /**
     * Declare the invoice permissions and keep `laravel-authorization`'s
     * resolutions in a store that outlives a check, as a worker's would.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function resolveApplicationConfiguration(mixed $app): void
    {
        parent::resolveApplicationConfiguration($app);

        $app->make('config')->set('authorization.permission_enums', [InvoicePermission::class]);
        $app->make('config')->set('authorization.cache.store', 'array');
    }

    /**
     * A person granted the refund at the tenant, reaching every tenant below.
     *
     * @param  string  $tenantId
     * @return \Tests\Fixtures\Authorization\Member
     *
     * @throws \Throwable
     */
    private function grantedAt(string $tenantId): Member
    {
        $person  = Member::query()->create(['name' => 'Ada Lovelace', 'email' => 'ada@example.test']);
        $service = $this->app?->make(GrantService::class) ?? self::fail('The application has not booted.');

        $service->grantPermission($person, InvoicePermission::REFUND->value, tenant: self::tenant($tenantId), includeSubtree: true);

        return $person;
    }

    /**
     * Whether the person may refund in the tenant.
     *
     * @param  \Tests\Fixtures\Authorization\Member  $person
     * @param  string  $tenantId
     * @return bool
     */
    private function mayRefundIn(Member $person, string $tenantId): bool
    {
        $authorization = $this->app?->make(AuthorizationManager::class) ?? self::fail('The application has not booted.');

        return in_array(InvoicePermission::REFUND->value, $authorization->permissionsFor($person, AuthorizationScope::tenant(self::tenant($tenantId))), true);
    }

    /**
     * A copy of the link, held by the identity.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Link  $link
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return \SineMacula\Laravel\Sso\Models\Link
     */
    private static function copyLink(Link $link, Identity $identity): Link
    {
        self::assertInstanceOf(Model::class, $identity);

        $copy                = $link->replicate();
        $copy->identity_type = $identity->getMorphClass();
        $copy->identity_id   = self::keyOf($identity);
        $copy->subject_key   = hash('sha256', $copy->identity_type . $copy->identity_id);

        $copy->save();

        return $copy;
    }

    /**
     * The tenant the id names, as the tests' resolver names it.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     */
    private static function tenant(string $id): Reference
    {
        return str_starts_with($id, Account::PREFIX) ? new Reference(Account::TYPE, $id) : new Reference(Organisation::TYPE, $id);
    }
}
