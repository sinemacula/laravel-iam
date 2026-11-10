<?php

declare(strict_types = 1);

namespace Tests\Integration\Authorization;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose;
use SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy;
use SineMacula\Laravel\AuditLog\Records\Reference as AuditReference;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authorization\Contracts\GrantHook;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Iam\Audit\References;
use SineMacula\Laravel\Iam\Authorization\AuditAccessPolicyAdapter;
use SineMacula\Laravel\Iam\Authorization\PermissionCatalogue;
use SineMacula\Laravel\Iam\Exceptions\UnresolvedReferenceException;
use SineMacula\Laravel\Iam\Tenancy\Membership;
use SineMacula\Laravel\Iam\Testing\FakeMemberships;
use Tests\Concerns\MigratesAuthorization;
use Tests\Concerns\RunsAtIsolationLevels;
use Tests\Fixtures\Authorization\GrantedSeat;
use Tests\Fixtures\Authorization\Organisation;
use Tests\Fixtures\Authorization\OrganisationTenancy;
use Tests\Fixtures\Authorization\RecordingGrantHook;
use Tests\Fixtures\Authorization\Staff;
use Tests\Fixtures\Authorization\UnscopedTenancy;
use Tests\TestCase;

/**
 * Integration tests of audit-log's access policy answered from
 * `laravel-authorization`'s grants (IAM-6.10): it is what audit-log resolves;
 * each read purpose has its own permissions, so a viewer may read and be denied
 * export; a grant, platform-wide or a tenant's, sees only the tenants it is
 * decided in, never the whole trail, and a tenant whose own decision denies it
 * is left out; a category's grant only that category and an own-activity grant
 * only the viewer's own activity; a scope is never wider than a grant, so
 * tenants
 * whose grants share no category see nothing; an empty list sees nothing;
 * a permission an authentication requirement guards is not held; grants beyond
 * audit-log's limits are refused rather than truncated; and a viewer named by a
 * reference that names nobody is refused.
 *
 * The grants are read on the storage connection, so each answer runs at the
 * connection's own level on every engine, then at READ COMMITTED and REPEATABLE
 * READ on MySQL and PostgreSQL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuditAccessPolicyAdapter::class)]
final class AuditAccessPolicyAdapterTest extends TestCase
{
    use MigratesAuthorization, RunsAtIsolationLevels;

    /** @var string The contract audit-log resolves its policy by. */
    private const string POLICY = AuditAccessPolicy::class;

    /** @var string A tenant the viewer is a member of. */
    private const string FIRST = 'org-1';

    /** @var string Another tenant the viewer is a member of. */
    private const string SECOND = 'org-2';

    /** @var \SineMacula\Laravel\Iam\Testing\FakeMemberships The viewer's memberships. */
    private FakeMemberships $memberships;

    /**
     * Store the catalogue's permissions, so they can be granted; record grant
     * hooks rather than widen anyone's scope; resolve the organisations; and
     * fake the memberships.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        foreach ((new PermissionCatalogue)->permissions() as $definition) {
            Permission::query()->create(['name' => $definition->name]);
        }

        $this->app?->instance(GrantHook::class, new RecordingGrantHook);
        $this->app?->singleton(TenantResolver::class, OrganisationTenancy::class);

        $this->memberships = FakeMemberships::fake($this->app);
    }

    /**
     * Forget any morph map a test set.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Relation::morphMap([], false);

        parent::tearDown();
    }

    /**
     * Audit-log resolves this package's policy, once, in place of its own.
     *
     * @return void
     */
    public function testAuditLogResolvesThePolicy(): void
    {
        self::assertInstanceOf(AuditAccessPolicyAdapter::class, self::policy());
        self::assertSame(self::policy(), self::policy());
    }

    /**
     * A viewer granted nothing sees nothing.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAViewerGrantedNothingSeesNothing(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $viewer = $this->viewer();

        $this->memberships->grant($viewer, Membership::of(self::FIRST));

        self::assertTrue(self::policy()->scope($viewer, ReadPurpose::READ)->isDenied());
    }

    /**
     * A platform-wide grant of a purpose sees the viewer's tenants for that
     * purpose alone: the viewer pages through their trail and is denied export.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEachPurposeHasItsOwnPermission(): void
    {
        $viewer = $this->viewer('audit-log.read', 'audit-log.count');

        $this->member($viewer, self::FIRST);

        $read = self::policy()->scope($viewer, ReadPurpose::READ);

        self::assertSame([self::tenant(self::FIRST)], self::tenants($read));
        self::assertNull($read->categories());
        self::assertFalse($read->includesTenantless());
        self::assertSame($read->toArray(), self::policy()->scope($viewer, ReadPurpose::COUNT)->toArray());
        self::assertTrue(self::policy()->scope($viewer, ReadPurpose::EXPORT)->isDenied());
        self::assertTrue(self::policy()->scope($viewer, ReadPurpose::VERIFY)->isDenied());
    }

    /**
     * A platform-wide grant is never read as the whole trail: with no tenant to
     * decide it in, it sees nothing, and a tenant whose own decision denies the
     * purpose is left out of what it sees.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPlatformGrantSeesOnlyTheTenantsThatAllowIt(): void
    {
        $alone  = $this->viewer('audit-log.read');
        $denied = $this->viewer('audit-log.read');

        $denied->attachPolicy(Policy::query()->create([
            'name'     => 'no-trail-in-the-second-tenant',
            'document' => [
                'statements' => [
                    ['sid' => 'deny-trail', 'effect' => 'deny', 'actions' => ['audit-log.read']],
                ],
            ],
        ]), tenant: new Reference(Organisation::TYPE, self::SECOND), includeSubtree: false);

        $this->member($denied, self::FIRST, self::SECOND);

        self::assertTrue(self::policy()->scope($alone, ReadPurpose::READ)->isDenied());
        self::assertSame([self::tenant(self::FIRST)], self::tenants(self::policy()->scope($denied, ReadPurpose::READ)));
    }

    /**
     * A permission an authentication requirement guards is not held where it
     * guards it, whether the requirement guards a deny or the allow: the policy
     * cannot tell whether the reader's session meets it. A principal decided as
     * its identity in a membership tenant is held to it as well.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPermissionARequirementGuardsIsNotHeldThere(): void
    {
        $denied  = $this->viewer('audit-log.read');
        $allowed = $this->viewer();

        $denied->attachPolicy(self::guarded('deny-trail', 'deny'), tenant: new Reference(Organisation::TYPE, self::SECOND), includeSubtree: false);
        $allowed->attachPolicy(self::guarded('allow-trail', 'allow'));

        $this->member($denied, self::FIRST, self::SECOND);
        $this->member($allowed, self::FIRST);

        self::assertSame([self::tenant(self::FIRST)], self::tenants(self::policy()->scope($denied, ReadPurpose::READ)));
        self::assertTrue(self::policy()->scope($allowed, ReadPurpose::READ)->isDenied());

        $person = $this->viewer();
        $seat   = GrantedSeat::query()->create(['person_id' => $person->getKey(), 'tenant_id' => self::FIRST]);

        $this->member($person, self::SECOND);
        $this->grant($person, 'audit-log.read', self::SECOND);

        $person->attachPolicy(self::guarded('deny-seat-trail', 'deny'), tenant: new Reference(Organisation::TYPE, self::SECOND), includeSubtree: false);

        self::assertTrue(self::policy()->scope(AuditReference::to($seat), ReadPurpose::READ)->isDenied());
    }

    /**
     * A platform-wide grant of categories sees the viewer's tenants in them
     * alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPlatformGrantOfCategoriesSeesThemAlone(): void
    {
        $viewer = $this->viewer('audit-log.export.security', 'audit-log.export.audit');

        $this->member($viewer, self::FIRST);

        $scope = self::policy()->scope($viewer, ReadPurpose::EXPORT);

        self::assertSame([self::tenant(self::FIRST)], self::tenants($scope));
        self::assertSame(['audit', 'security'], $scope->categories());
    }

    /**
     * Grants in tenants the viewer is a member of see those tenants alone, in
     * every category, and a tenant it holds nothing in, and its platform
     * membership, are left out.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testTenantGrantsSeeTheirTenantsAlone(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $viewer = $this->viewer();

        $this->grant($viewer, 'audit-log.read', self::FIRST);
        $this->grant($viewer, 'audit-log.read', self::SECOND);
        $this->memberships->grant($viewer, Membership::platform());
        $this->member($viewer, self::FIRST, self::SECOND, 'org-3');

        $scope = self::policy()->scope($viewer, ReadPurpose::READ);

        self::assertSame([self::tenant(self::FIRST), self::tenant(self::SECOND)], self::tenants($scope));
        self::assertNull($scope->categories());
        self::assertFalse($scope->includesTenantless());
    }

    /**
     * A tenant whose grant reaches some categories narrows every tenant to
     * them, and tenants whose grants share no category see nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheScopeIsNeverWiderThanAnyTenantsGrant(): void
    {
        $narrowed = $this->viewer();
        $disjoint = $this->viewer();

        $this->grant($narrowed, 'audit-log.read', self::FIRST);
        $this->grant($narrowed, 'audit-log.read.security', self::SECOND);
        $this->grant($narrowed, 'audit-log.read.audit', self::SECOND);
        $this->member($narrowed, self::FIRST, self::SECOND);

        $this->grant($disjoint, 'audit-log.read.security', self::FIRST);
        $this->grant($disjoint, 'audit-log.read.audit', self::SECOND);
        $this->member($disjoint, self::FIRST, self::SECOND);

        $scope = self::policy()->scope($narrowed, ReadPurpose::READ);

        self::assertSame([self::tenant(self::FIRST), self::tenant(self::SECOND)], self::tenants($scope));
        self::assertSame(['audit', 'security'], $scope->categories());
        self::assertTrue(self::policy()->scope($disjoint, ReadPurpose::READ)->isDenied());
    }

    /**
     * An own-activity grant sees only the viewer's own activity, in the tenants
     * it is held in, platform-wide or not, and nowhere with no tenant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnOwnActivityGrantSeesOnlyTheViewersOwnActivity(): void
    {
        $everywhere = $this->viewer('audit-log.read.own');
        $inTenant   = $this->viewer();

        self::assertTrue(self::policy()->scope($everywhere, ReadPurpose::READ)->isDenied());

        $this->member($everywhere, self::FIRST, self::SECOND);
        $this->grant($inTenant, 'audit-log.read.own', self::FIRST);
        $this->member($inTenant, self::FIRST);

        $platform = self::policy()->scope($everywhere, ReadPurpose::READ);
        $tenant   = self::policy()->scope($inTenant, ReadPurpose::READ);

        self::assertSame([self::tenant(self::FIRST), self::tenant(self::SECOND)], self::tenants($platform));
        self::assertSame([[References::type(Staff::class), self::keyOf($everywhere)]], self::about($platform));
        self::assertSame([self::tenant(self::FIRST)], self::tenants($tenant));
        self::assertSame([[References::type(Staff::class), self::keyOf($inTenant)]], self::about($tenant));
    }

    /**
     * A principal, named by its reference as a principal that is no user is, is
     * decided as itself, in its own tenant, with no memberships bound, and seen
     * by its identity and itself.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPrincipalIsDecidedInItsOwnTenant(): void
    {
        $person = $this->viewer();
        $seat   = GrantedSeat::query()->create(['person_id' => $person->getKey(), 'tenant_id' => self::FIRST]);

        $this->app?->forgetInstance(FakeMemberships::MEMBERSHIPS);

        $seat->givePermission('audit-log.verify', tenant: new Reference(Organisation::TYPE, self::FIRST));
        $seat->givePermission('audit-log.read.own');

        self::assertSame([self::tenant(self::FIRST)], self::tenants(self::policy()->scope(AuditReference::to($seat), ReadPurpose::VERIFY)));
        self::assertCount(2, self::about(self::policy()->scope(AuditReference::to($seat), ReadPurpose::READ)));
    }

    /**
     * A principal's grant reaching a tenant its identity is a member of, but
     * where `laravel-authentication`'s tenant access does not let it act,
     * widens nothing: no check would let that principal use it there. Its
     * identity's own grant there holds across every principal, so it is seen.
     *
     * @param  ?string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEveryIsolationLevel')]
    public function testAPrincipalSeesNoMembershipTenantItCannotActIn(?string $level): void
    {
        self::runAtIsolationLevel($level);

        $person = $this->viewer();
        $seat   = GrantedSeat::query()->create(['person_id' => $person->getKey(), 'tenant_id' => self::FIRST]);

        $this->member($person, self::SECOND);

        $seat->givePermission('audit-log.read', tenant: new Reference(Organisation::TYPE, self::SECOND));

        self::assertTrue(self::policy()->scope(AuditReference::to($seat), ReadPurpose::READ)->isDenied());

        $this->grant($person, 'audit-log.read', self::SECOND);

        self::assertSame([self::tenant(self::SECOND)], self::tenants(self::policy()->scope(AuditReference::to($seat), ReadPurpose::READ)));
    }

    /**
     * A principal's grant reaching a tenant its identity is a member of, where
     * `laravel-authentication`'s tenant access lets it act, is seen there.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPrincipalSeesAMembershipTenantItMayActIn(): void
    {
        $person = $this->viewer();
        $seat   = GrantedSeat::query()->create(['person_id' => $person->getKey(), 'tenant_id' => self::FIRST]);

        $this->member($person, self::SECOND);
        $this->app?->instance(TenantAccess::class, new class implements TenantAccess {
            /**
             * Whether the principal may act in the tenant: in any.
             *
             * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
             * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
             * @return bool
             */
            #[\Override]
            public function mayActIn(Principal $principal, ?Tenant $tenant): bool
            {
                return true;
            }
        });

        $seat->givePermission('audit-log.read', tenant: new Reference(Organisation::TYPE, self::SECOND));

        self::assertSame([self::tenant(self::SECOND)], self::tenants(self::policy()->scope(AuditReference::to($seat), ReadPurpose::READ)));
    }

    /**
     * A viewer named by a reference, read through the morph map, is decided as
     * the model it names; one that names nobody is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAViewerNamedByAReferenceIsTheModelItNames(): void
    {
        Relation::morphMap(['staff' => Staff::class]);

        $viewer = $this->viewer('audit-log.read');

        $this->member($viewer, self::FIRST);

        self::assertSame([self::tenant(self::FIRST)], self::tenants(self::policy()->scope(AuditReference::of('staff', self::keyOf($viewer)), ReadPurpose::READ)));

        $this->expectException(UnresolvedReferenceException::class);

        self::policy()->scope(AuditReference::of(Staff::class, '999999'), ReadPurpose::READ);
    }

    /**
     * A reference to no model is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReferenceToNoModelIsRefused(): void
    {
        $this->expectException(UnresolvedReferenceException::class);

        self::policy()->scope(AuditReference::of('nothing', '1'), ReadPurpose::READ);
    }

    /**
     * Grants in more tenants than audit-log's scope holds are refused, never
     * truncated.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testGrantsBeyondTheLimitAreRefused(): void
    {
        $viewer  = $this->viewer();
        $tenants = array_map(static fn (int $index): string => 'org-' . $index, range(1, AccessScope::MAX_TENANTS + 1));

        foreach ($tenants as $tenant) {
            $this->grant($viewer, 'audit-log.read', $tenant);
        }

        $this->member($viewer, ...$tenants);

        $this->expectException(\InvalidArgumentException::class);

        self::policy()->scope($viewer, ReadPurpose::READ);
    }

    /**
     * A tenant `laravel-authorization` cannot scope to is refused.
     *
     * @return void
     */
    public function testATenantThatCannotBeScopedIsRefused(): void
    {
        $viewer = $this->viewer();

        $this->member($viewer, self::FIRST);
        $this->app?->instance(TenantResolver::class, new UnscopedTenancy);

        $this->expectException(UnresolvedReferenceException::class);

        self::policy()->scope($viewer, ReadPurpose::READ);
    }

    /**
     * Name the catalogue among `laravel-authorization`'s permission providers,
     * set before any provider registers.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function resolveApplicationConfiguration(mixed $app): void
    {
        parent::resolveApplicationConfiguration($app);

        assert($app instanceof Application);

        $app->make('config')->set('authorization.permission_providers', [PermissionCatalogue::class]);
    }

    /**
     * A viewer, granted the permissions platform-wide.
     *
     * @param  string  ...$permissions
     * @return \Tests\Fixtures\Authorization\Staff
     */
    private function viewer(string ...$permissions): Staff
    {
        $viewer = Staff::query()->create(['name' => 'Ada Lovelace', 'email' => uniqid('ada', true) . '@example.test']);

        foreach ($permissions as $permission) {
            $viewer->givePermission($permission);
        }

        return $viewer;
    }

    /**
     * Grant the viewer the permission in the tenant.
     *
     * @param  \Tests\Fixtures\Authorization\Staff  $viewer
     * @param  string  $permission
     * @param  string  $tenantId
     * @return void
     */
    private function grant(Staff $viewer, string $permission, string $tenantId): void
    {
        $viewer->givePermission($permission, tenant: new Reference(Organisation::TYPE, $tenantId));
    }

    /**
     * Make the viewer a member of the tenants.
     *
     * @param  \Tests\Fixtures\Authorization\Staff  $viewer
     * @param  string  ...$tenantIds
     * @return void
     */
    private function member(Staff $viewer, string ...$tenantIds): void
    {
        foreach ($tenantIds as $tenantId) {
            $this->memberships->grant($viewer, Membership::of($tenantId));
        }
    }

    /**
     * A policy whose one statement, of the effect, names reading the trail
     * under a multifactor requirement.
     *
     * @param  string  $name
     * @param  string  $effect
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function guarded(string $name, string $effect): Policy
    {
        return Policy::query()->create([
            'name'     => $name,
            'document' => [
                'statements' => [
                    [
                        'sid'        => 'guarded-trail',
                        'effect'     => $effect,
                        'actions'    => ['audit-log.read'],
                        'conditions' => ['authentication_requirement' => ['authentication' => ['multifactor' => []]]],
                    ],
                ],
            ],
        ]);
    }

    /**
     * The policy audit-log resolves.
     *
     * @return \SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy
     */
    private static function policy(): AuditAccessPolicy
    {
        $policy = app()->make(self::POLICY);

        self::assertInstanceOf(AuditAccessPolicy::class, $policy);

        return $policy;
    }

    /**
     * The tenant as a scope lists it.
     *
     * @param  string  $tenantId
     * @return array{0: string, 1: string}
     */
    private static function tenant(string $tenantId): array
    {
        return [References::TENANT_TYPE, $tenantId];
    }

    /**
     * The tenants the scope sees, as it lists them.
     *
     * @param  \SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @return list<array{0: string, 1: string}>
     */
    private static function tenants(AccessScope $scope): array
    {
        $tenants = $scope->toArray()['tenants'] ?? null;

        self::assertIsArray($tenants);

        /** @var list<array{0: string, 1: string}> $tenants */
        return $tenants;
    }

    /**
     * The references the scope sees the activity of, as it lists them.
     *
     * @param  \SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @return list<array{0: string, 1: string}>
     */
    private static function about(AccessScope $scope): array
    {
        $about = $scope->toArray()['about'] ?? null;

        self::assertIsArray($about);

        /** @var list<array{0: string, 1: string}> $about */
        return $about;
    }

    /**
     * The model's key, as a string.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return string
     */
    private static function keyOf(Model $model): string
    {
        $key = $model->getKey();

        return is_int($key) || is_string($key) ? (string) $key : self::fail('The model has no key.');
    }
}
